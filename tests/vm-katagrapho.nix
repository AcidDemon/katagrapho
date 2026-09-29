# NixOS VM test for the katagrapho module.
#
# module-eval asserts what the module *renders*. This asserts what the host
# then *does*: that keygen runs and lands the key with an owner the recorder
# can read, that the setuid wrapper works for a caller in the exec group, that
# concurrent sessions produce one unbroken chain, that the recorded user cannot
# touch their own recording, that retention deletes recordings without breaking
# verification, and that keygen repairs an ownership change instead of skipping.
#
# Run with: nix build .#checks.x86_64-linux.vm-test
{ pkgs, katagraphoFlake }:
let
  # Fixed throwaway keypair, generated for this test only. The public half is
  # installed to /etc/age so the test covers the module's recipientFile
  # plumbing and the lexical path check that accepts an /etc store symlink.
  testPubKey = "age17gnsphc43g7eehckaxq6ecqkamaqd7prxddxfzul3950wqgakd9qu7zldg";
  testSecretKey = "AGE-SECRET-KEY-1R59K78Z3TUK27KF3K90WXYKZCJC7UCUAYQC32SFGUXY4HGAGMQ4SAGUG2R";
in
pkgs.testers.nixosTest {
  name = "katagrapho";

  nodes.machine =
    { ... }:
    {
      imports = [ katagraphoFlake.nixosModules.katagrapho ];

      services.katagrapho = {
        enable = true;
        encryption.recipientFile = "/etc/age/recipients.txt";
      };

      environment.etc."age/recipients.txt".text = "${testPubKey}\n";

      # Materialize /etc as symlinks into the store rather than as real files,
      # exactly as on a deployed host. This is the shape a canonicalize-then-
      # allowlist recipient check gets wrong.
      system.etc.overlay.enable = false;

      # The wrapper is 0550 katagrapho:katagrapho, so a caller has to be in the
      # exec group. On a real host that member is the epitropos proxy account.
      users.users.tester = {
        isNormalUser = true;
        extraGroups = [ "katagrapho" ];
      };

      # The other half of the two-group model: an auditor reads recordings and
      # chain state and must never need root, while being unable to record.
      users.users.auditor = {
        isNormalUser = true;
        extraGroups = [ "katagrapho-readers" ];
      };

      environment.systemPackages = [ pkgs.age ];
      virtualisation.memorySize = 1024;
    };

  testScript = ''
    import json, shlex

    SESSIONS = [f"sess{i}" for i in range(1, 9)]
    STORE = "/var/log/ssh-sessions"
    STATE = "/var/lib/katagrapho"
    WRAPPER = "/run/wrappers/bin/katagrapho"


    def stream(sid):
        """A minimal katagrapho-v1 record stream, as epitropos would emit."""
        return "".join(
            json.dumps(rec, separators=(",", ":")) + "\n"
            for rec in [
                {
                    "kind": "header", "v": "katagrapho-v1", "session_id": sid,
                    "user": "tester", "host": "machine", "boot_id": "b", "part": 0,
                    "started": 1.0, "epitropos_version": "0",
                    "epitropos_commit": "x", "audit_session_id": None,
                },
                {"kind": "out", "t": 0.5, "b": "bWFya2Vy"},
                {"kind": "chunk", "seq": 0, "bytes": 10, "messages": 1,
                 "elapsed": 0.5, "sha256": "aa" * 32},
                {"kind": "end", "t": 2.0, "reason": "eof", "exit_code": 0},
            ]
        )


    def recording(sid):
        return f"{STORE}/tester/{sid}.part0.cast.age"


    def mode_of(path):
        return machine.succeed(f"stat -c %U:%G:%a {path}").strip()


    machine.wait_for_unit("multi-user.target")
    # A oneshot with RemainAfterExit stays active, so this also proves it did
    # not fail on first boot.
    machine.wait_for_unit("katagrapho-keygen.service")

    with subtest("keygen lands key material the recorder can actually read"):
        # 0400 owned by the recorder: if this is wrong the recorder runs
        # key-less and records every session without a manifest.
        assert mode_of(f"{STATE}/signing.key") == "katagrapho:katagrapho:400", mode_of(f"{STATE}/signing.key")
        # Both directories carry the setgid bit, which is what puts new
        # recordings and new chain state in the readers group. tmpfiles cannot
        # do this on a fresh host: it runs before keygen and before any
        # recording exists, so the group has to be inherited by construction.
        assert mode_of(STATE) == "katagrapho:katagrapho-readers:2750", mode_of(STATE)
        assert mode_of(STORE) == "katagrapho:katagrapho-readers:2750", mode_of(STORE)
        # The public key is public; anything that verifies needs it.
        machine.succeed(f"runuser -u auditor -- cat {STATE}/signing.pub > /dev/null")
        # The private key is not.
        machine.fail(f"runuser -u auditor -- cat {STATE}/signing.key")
        machine.fail(f"runuser -u tester -- cat {STATE}/signing.key")

    with subtest("the setuid wrapper is installed as the module declares"):
        assert mode_of(WRAPPER) == "katagrapho:katagrapho:6550", mode_of(WRAPPER)

    with subtest("the audit tools are on PATH"):
        machine.succeed("katagrapho-verify --help")
        machine.succeed("katagrapho-keygen --version")

    with subtest("eight concurrent sessions record through the setuid wrapper"):
        for sid in SESSIONS:
            machine.succeed(
                f"printf %s {shlex.quote(stream(sid))} > /tmp/{sid}.kgv1 && chmod 644 /tmp/{sid}.kgv1"
            )
        # All at once: the chain is advanced under one flock, and a lost update
        # would leave two log lines claiming the same predecessor.
        starts = " ".join(
            f"runuser -u tester -- sh -c '{WRAPPER} --session-id {sid} "
            f"--recipient-file /etc/age/recipients.txt < /tmp/{sid}.kgv1' &"
            for sid in SESSIONS
        )
        machine.succeed(f"({starts} wait)")
        for sid in SESSIONS:
            machine.succeed(f"test -f {recording(sid)}")
            machine.succeed(f"test -f {recording(sid)}.manifest.json")

    with subtest("recordings and their directory are beyond the recorded user"):
        assert mode_of(recording(SESSIONS[0])) == "katagrapho:katagrapho-readers:440", mode_of(recording(SESSIONS[0]))
        assert mode_of(f"{STORE}/tester") == "katagrapho:katagrapho-readers:2750", mode_of(f"{STORE}/tester")
        rec = recording(SESSIONS[0])
        machine.fail(f"runuser -u tester -- sh -c 'cat {rec}'")
        machine.fail(f"runuser -u tester -- sh -c 'echo x >> {rec}'")
        machine.fail(f"runuser -u tester -- sh -c 'rm -f {rec}'")
        machine.fail(f"runuser -u tester -- sh -c 'ls {STORE}/tester'")

    with subtest("every sidecar verifies on its own"):
        # Per file, because a directory walk stops at the first failure and
        # would hide how many of the eight are affected.
        broken = {}
        for sid in SESSIONS:
            rc, out = machine.execute(f"katagrapho-verify {recording(sid)}.manifest.json 2>&1")
            if rc != 0:
                broken[sid] = out.strip()
        # Print the offender in full: this check caught a digest that verified
        # in memory and failed off disk, and the manifest contents were what
        # identified the field responsible.
        for sid in broken:
            print(machine.succeed(f"cat {recording(sid)}.manifest.json"))
        assert not broken, f"sidecars failed to verify: {broken}"

    with subtest("the chain and the signed log both verify"):
        out = machine.succeed(f"katagrapho-verify --check-chain {STORE}")
        assert f"{len(SESSIONS)} signed line(s) verified" in out, out
        assert f"{len(SESSIONS)} manifests verified (chain ok)" in out, out
        # One line per session, each linking to the one before it.
        lines = machine.succeed(f"wc -l < {STATE}/head.hash.log").strip()
        assert lines == str(len(SESSIONS)), f"expected {len(SESSIONS)} log lines, got {lines}"
        # head.hash is the last log line's manifest hash. verify already
        # cross-checks this; assert it directly so a failure is unambiguous.
        head = machine.succeed(f"cat {STATE}/head.hash").strip()
        tip = machine.succeed(f"tail -1 {STATE}/head.hash.log | cut -d' ' -f5").strip()
        assert head == tip, f"head.hash {head} != log tip {tip}"

    with subtest("an auditor verifies the whole corpus without root"):
        # The point of the readers group. If this needs root, the group model
        # is decoration: head.hash is the truncation anchor, so a verifier that
        # cannot read it silently skips the check that matters most.
        machine.succeed(f"runuser -u auditor -- cat {STATE}/head.hash > /dev/null")
        machine.succeed(f"runuser -u auditor -- cat {STATE}/head.hash.log > /dev/null")
        machine.succeed(f"runuser -u auditor -- cat {recording(SESSIONS[0])} > /dev/null")
        out = machine.succeed(f"runuser -u auditor -- katagrapho-verify --check-chain {STORE}")
        assert f"{len(SESSIONS)} manifests verified (chain ok)" in out, out
        # Reading is not recording: the auditor is not in the exec group.
        machine.fail(
            f"runuser -u auditor -- sh -c '{WRAPPER} --session-id x --no-encrypt < /dev/null'"
        )

    with subtest("a recording decrypts to exactly the bytes that were piped in"):
        machine.succeed("install -m600 /dev/null /tmp/id && echo '${testSecretKey}' > /tmp/id")
        sid = SESSIONS[0]
        machine.succeed(f"age -d -i /tmp/id {recording(sid)} > /tmp/out.kgv1")
        machine.succeed(f"cmp /tmp/{sid}.kgv1 /tmp/out.kgv1")

    with subtest("keygen repairs an ownership change instead of skipping it"):
        # What renaming services.katagrapho.user does to an existing host.
        machine.succeed(f"chown root:root {STATE}/signing.key")
        machine.succeed("systemctl restart katagrapho-keygen.service")
        assert mode_of(f"{STATE}/signing.key") == "katagrapho:katagrapho:400", mode_of(f"{STATE}/signing.key")
        # And it must not have rotated: the existing manifests still verify.
        machine.succeed(f"katagrapho-verify --check-chain {STORE}")

    with subtest("keygen rebuilds a missing public half from the private key"):
        before = machine.succeed(f"sha256sum < {STATE}/signing.pub").strip()
        machine.succeed(f"rm {STATE}/signing.pub")
        machine.succeed("systemctl restart katagrapho-keygen.service")
        assert machine.succeed(f"sha256sum < {STATE}/signing.pub").strip() == before
        machine.succeed(f"katagrapho-verify --check-chain {STORE}")

    with subtest("an unsigned recording is reported, not ignored"):
        # What a session recorded while the key was unreadable looks like.
        machine.succeed(f"install -o katagrapho -g katagrapho-readers -m440 /dev/null {STORE}/tester/rogue.part0.cast.age")
        machine.fail(f"katagrapho-verify --check-chain {STORE}")
        out = machine.fail(f"katagrapho-verify --check-chain {STORE} 2>&1")
        assert "UNSIGNED recording" in out, out
        machine.succeed(f"rm {STORE}/tester/rogue.part0.cast.age")

    with subtest("retention deletes recordings and keeps the chain verifiable"):
        machine.succeed(f"find {STORE} -type f -exec touch -d '100 days ago' {{}} +")
        machine.succeed("systemctl start katagrapho-cleanup.service")
        # The recordings are gone...
        for sid in SESSIONS:
            machine.fail(f"test -f {recording(sid)}")
        # ...every manifest survived, because the manifests are the chain...
        for sid in SESSIONS:
            machine.succeed(f"test -f {recording(sid)}.manifest.json")
        # ...and verification still passes, reporting them as pruned rather
        # than as tampering. This is the case that failed on every host from
        # day 91 when retention deleted sidecars too.
        out = machine.succeed(f"katagrapho-verify --check-chain {STORE}")
        assert "pruned by retention" in out, out
        machine.succeed(f"test -f {STATE}/head.hash.log")

    # Each tamper case starts from the pristine log: otherwise the first
    # failure found is the previous case's edit, and the later assertions pass
    # or fail for the wrong reason.
    machine.succeed(f"cp {STATE}/head.hash.log /tmp/log.pristine")

    with subtest("an edited log line is caught"):
        machine.succeed(f"sed -i 's/ tester / mallory /' {STATE}/head.hash.log")
        out = machine.fail(f"katagrapho-verify --check-chain {STORE} 2>&1")
        assert "log_hash does not match" in out, out

    with subtest("a truncated log tail is caught"):
        machine.succeed(f"cp /tmp/log.pristine {STATE}/head.hash.log")
        machine.succeed(f"sed -i '$d' {STATE}/head.hash.log")
        out = machine.fail(f"katagrapho-verify --check-chain {STORE} 2>&1")
        # head.hash still names the tip the deleted line carried.
        assert "does not match the last signed log entry" in out, out
  '';
}
