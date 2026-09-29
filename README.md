# katagrapho

Setuid+setgid binary for tamper-proof session recording with age encryption. It reads a session record stream from stdin, encrypts it, and writes files that the recorded user **cannot modify or delete**.

Named after the Greek *katagrapho* (to write down/record), the process that commits every session to disk.

## How it works

`katagrapho` reads stdin and writes to `/var/log/ssh-sessions/<user>/<session-id>.part<N>.cast.age`. It runs setuid as a dedicated `katagrapho` user and setgid as the `katagrapho` group. Recordings are created mode `0440` in a directory the recorded user does not own, so they cannot `chmod`, overwrite, or unlink them.

The stdin format is the katagrapho-v1 record stream produced by [epitropos](https://github.com/AcidDemon/epitropos): one JSON object per line, each with a `kind` field. It is not asciicast, though the decrypted payload replays as a terminal session.

What the binary guarantees:

- Streaming age encryption via the `age` crate. Data is encrypted as it arrives and never buffered in plaintext.
- Encryption on by default. It refuses to run without `--recipient-file`; plaintext needs an explicit `--no-encrypt`.
- Interrupted recordings are kept as evidence rather than deleted. On a catchable stop (SIGTERM or SIGINT) the encrypted stream is finalized and stays decryptable. A hard kill (SIGKILL, OOM, power loss) leaves the in-progress part unfinalizable, but earlier parts stay intact because of size-based rotation.
- File creation goes through `openat()` with `O_CREAT|O_EXCL|O_NOFOLLOW`.
- The username comes from the kernel, resolved from the real UID with `getpwuid()`, never from an argument.
- The environment is sanitized at startup, so `LD_PRELOAD`, `LD_LIBRARY_PATH` and friends are dropped before anything else runs.
- Size limits: 512 MiB per part, 4 GiB per session. Reaching the part limit rotates to `.part<N+1>`; reaching the session limit ends the recording.
- Full RELRO, PIE and overflow checks. `SIGXFSZ` is ignored so an oversized write returns `EFBIG` instead of killing the process mid-stream and leaving an undecryptable part.

## Installation (NixOS)

```nix
# flake.nix
{
  inputs.katagrapho.url = "github:AcidDemon/katagrapho";

  outputs = { self, nixpkgs, katagrapho, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        katagrapho.nixosModules.default
        {
          services.katagrapho = {
            enable = true;
            encryption.recipientFile = "/etc/age/session-recording.pub";
            # encryption.required = true;              # default
            # encryption.plugins = [ pkgs.age-plugin-yubikey ];
            # logRotation.enable = true;               # default
            # logRotation.maxAgeDays = 90;             # default
            # logRotation.frequency = "weekly";        # default
            # user = "katagrapho";                     # default
            # group = "katagrapho";                    # default
          };
        }
      ];
    };
  };
}
```

This creates the `katagrapho` user, the `katagrapho` and `katagrapho-readers` groups, the storage directory, the setuid/setgid wrapper at `/run/wrappers/bin/katagrapho`, a keygen unit, and a weekly cleanup timer. It also puts `katagrapho-verify` and `katagrapho-keygen` on the system path.

Set `encryption.plugins` when any recipient is a plugin recipient such as `age1yubikey1…`. The plugin binary has to be available to katagrapho at encrypt time, and because the binary sanitizes its own environment it rebuilds `PATH` from that package set alone. Native `age1…` X25519 recipients need nothing here.

`encryption.recipientFile` and `encryption.required` describe the host's intent. The module does not pass them to the binary: epitropos execs katagrapho and supplies `--recipient-file` from `services.epitropos.encryption.recipientFile`. Point both at the same file. An assertion checks that a host requiring encryption has a proxy configured to pass a recipient, so the mismatch fails the build instead of denying every login at runtime.

## Usage

Designed to be spawned by epitropos, the PTY proxy, but it also runs standalone:

```sh
# With encryption (default)
some-source | /run/wrappers/bin/katagrapho --session-id <ID> --recipient-file /etc/age/recipients.txt

# Without encryption (must be explicit)
some-source | /run/wrappers/bin/katagrapho --session-id <ID> --no-encrypt
```

The username is determined automatically from the calling process UID.

## Architecture

`katagrapho` is one half of a two-component system:

| Component | Role |
|---|---|
| **[epitropos](https://github.com/AcidDemon/epitropos)** | PTY proxy. PAM-triggered, owns the terminal, produces the katagrapho-v1 record stream |
| **katagrapho** | Storage writer. Encrypts with age, writes tamper-proof files, signs manifests |

IPC is a stdin pipe. `epitropos` spawns `katagrapho` as a child process and pipes the stream to it.

## Permission model

```
/var/log/ssh-sessions/              katagrapho:katagrapho-readers  2750
/var/log/ssh-sessions/<user>/       katagrapho:katagrapho-readers  2750
/var/log/ssh-sessions/<user>/*.age  katagrapho:katagrapho-readers  0440
/var/lib/katagrapho/                katagrapho:katagrapho-readers  2750
/var/lib/katagrapho/signing.key     katagrapho:katagrapho          0400
/var/lib/katagrapho/signing.pub     katagrapho:katagrapho-readers  0444
/var/lib/katagrapho/head.hash       katagrapho:katagrapho-readers  0640
/var/lib/katagrapho/head.hash.log   katagrapho:katagrapho-readers  0640
/run/wrappers/bin/katagrapho        katagrapho:katagrapho          0550 setuid+setgid
```

Two groups, doing two different jobs. `katagrapho-readers` can read recordings and the chain state, which is what an auditor or a shipping daemon needs. The `katagrapho` group is on the wrapper, so its members may *execute* the recorder; it grants no read access to the corpus. The setgid bit on the storage directory is what propagates `katagrapho-readers` down to new per-user directories and recordings.

The recorded user owns nothing in this chain. Only `root` and members of `katagrapho-readers` can read the recordings.

## Verifying recordings

Each recording gets a signed `.manifest.json` sidecar (ed25519), and every manifest is linked into a per-host append-only hash chain (`head.hash` and `head.hash.log`).

There are two chains, not one. The manifests chain to each other through `prev_manifest_hash`, and `head.hash.log` is a second chain over the same events: each line carries the hash of the line before it plus an ed25519 signature over its own contents. The log therefore stands on its own. It detects an edited line, a removed line and a reordered line even if every manifest and every recording on the host has been deleted, which is the case the manifest chain cannot speak to. Lines written by a build from before log signing have five fields instead of eight; they verify as legacy and are accepted only as a contiguous prefix, so nobody can strip the signatures off newer lines and pass them off as old records.

```sh
# Verify one sidecar: manifest signature AND that the recording file still
# hashes to the signed value (detects on-disk tampering of the recording).
katagrapho-verify /var/log/ssh-sessions/<user>/<id>.part0.cast.age.manifest.json

# Verify a whole tree and the chain, anchored to the persisted head.hash so
# deletion of the newest recordings (tail truncation) is detected too.
katagrapho-verify --check-chain --chain-dir /var/lib/katagrapho /var/log/ssh-sessions
```

`--check-chain` verifies the log first, because it is the record that survives the manifests being deleted and therefore the thing an attacker edits first. It then checks that `head.hash` agrees with the last signed log entry (both are written under one lock, so they cannot legitimately disagree) and walks the manifests as a single path from one genesis to the tip `head.hash` names. Walking the path, rather than only checking that every `prev_manifest_hash` is present, is what rejects a fork, a second genesis and a parallel branch signed with the host's own key.

The recording is located from the sidecar's own name, not from the `recording_file` field inside the manifest. That matters off-host: the collector stores the same bytes under a different name, while the signed field keeps recording the original one.

A directory walk also reports two things a manifest-driven walk would miss. Recordings with no sidecar at all are listed as unsigned and exit non-zero, because that is what a recording written while the signing key was unreadable looks like. Recordings that retention has deleted while their sidecar survives are reported as pruned, separately from a hash mismatch: the signature and the chain still verify, only the content re-hash cannot run.

Retention deletes recordings and keeps manifests, so an aged host still verifies. Sidecars are about a kilobyte each and they are the chain; deleting them breaks referential integrity for everything that outlived them.

**Integrity is availability-first.** If the signing key is unavailable, recording still proceeds but the session is written without a manifest, logged at `LOG_CRIT`, so wire that to alerting. `katagrapho-keygen` hard-fails if it cannot make the key readable by the recording user, and it re-asserts ownership on every boot rather than skipping when the key already exists. Renaming the recorder account used to leave the key owned by a uid that no longer existed, and every session after that was recorded unsigned.

## Building from source

```sh
# With Nix
nix build
nix flake check      # fmt, clippy, tests, hardening, module eval

# With Cargo
cargo build --release
cargo test
```

Requires Rust >= 1.85 (edition 2024).

## Dependencies

- `libc` for POSIX syscalls (`openat`, `getpwuid`, `umask`, `chown`)
- `age` for streaming encryption, with plugin support for recipients like `age1yubikey1…`
- `ed25519-dalek` and `rand` for manifest signing and key generation
- `sha2` and `hex` for recording and manifest digests
- `serde`, `serde_json` and `toml` for manifests and `/etc/katagrapho/config.toml`
- `thiserror` for the error type

## License

MIT
