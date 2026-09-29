# NixOS module for katagrapho.
# Consumed as: imports = [ inputs.katagrapho.nixosModules.default ];
flakeSelf:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.katagrapho;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    literalExpression
    ;

  # age plugin binaries (e.g. age-plugin-yubikey) collected into one bin dir.
  # katagrapho sanitizes its environment at startup, so it re-establishes PATH
  # from this trusted directory before loading recipients — that is how plugin
  # recipients (age1yubikey1…) resolve their plugin binary at encrypt time.
  pluginEnv = pkgs.symlinkJoin {
    name = "katagrapho-age-plugins";
    paths = cfg.encryption.plugins;
  };
  needConfig = cfg.encryption.plugins != [ ];
  configFile = (pkgs.formats.toml { }).generate "katagrapho-config.toml" {
    encryption.plugin_path = "${pluginEnv}/bin";
  };
in
{
  options.services.katagrapho = {
    enable = mkEnableOption "katagrapho session recording";

    package = mkOption {
      type = types.package;
      default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.katagrapho;
      defaultText = literalExpression "inputs.katagrapho.packages.\${system}.katagrapho";
      description = "The katagrapho package to use.";
    };

    group = mkOption {
      type = types.str;
      default = "katagrapho";
      description = ''
        Primary group of the recorder account, and the group on the setuid
        wrapper — so its members may *execute* the recorder. It grants no read
        access to recordings or to the signing key: those are owned by the
        katagrapho-readers group, which this module also creates.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "katagrapho";
      description = "Dedicated user that owns session recording files.";
    };

    storageDir = mkOption {
      type = types.path;
      default = "/var/log/ssh-sessions";
      readOnly = true;
      description = ''
        Directory where session recordings are stored.
        Hardcoded in the binary — do not change.
      '';
    };

    encryption = {
      recipientFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          Path to a file containing age public key(s) for encrypting
          recordings.

          This declares the host's intent; it is not handed to the binary by
          this module. katagrapho is exec'd by the proxy, which passes
          `--recipient-file` itself from
          {option}`services.epitropos.encryption.recipientFile`. Both are
          normally set to the same file, and the assertions below check that
          they agree rather than letting a host claim encryption it does not
          have.
        '';
      };

      required = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether encryption is required. When true (default), the binary
          refuses to run without `--recipient-file`, and this module asserts
          that whoever spawns it actually passes one.
        '';
      };

      plugins = mkOption {
        type = types.listOf types.package;
        default = [ ];
        example = literalExpression "[ pkgs.age-plugin-yubikey ]";
        description = ''
          age plugin packages required to encrypt to plugin recipients such
          as age1yubikey1…. Their bin directory is written to katagrapho's
          config and prepended to PATH at encrypt time. Native age1… X25519
          recipients need nothing here.
        '';
      };
    };

    logRotation = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable automatic cleanup of old session recordings.";
      };

      maxAgeDays = mkOption {
        type = types.ints.positive;
        default = 90;
        description = "Delete recordings older than this many days.";
      };

      frequency = mkOption {
        type = types.str;
        default = "weekly";
        description = "Cleanup frequency (systemd OnCalendar syntax).";
      };
    };
  };

  config = mkIf cfg.enable {

    assertions = [
      {
        assertion = !cfg.encryption.required || cfg.encryption.recipientFile != null;
        message = ''
          services.katagrapho.encryption.recipientFile must be set when
          services.katagrapho.encryption.required is true (the default).
          Set a recipient file or set encryption.required = false.
        '';
      }
      {
        # The recorder learns its recipient from the proxy's argv, so
        # katagrapho's own option being set proves nothing about what the
        # sessions on this host are actually encrypted to. Without this, a host
        # can pass every assertion here and still record plaintext — or, with
        # encryption.required, deny every login at runtime instead of failing
        # the build.
        assertion =
          !(cfg.encryption.required && (config.services.epitropos.enable or false))
          || (
            (config.services.epitropos.encryption.enable or false)
            && (config.services.epitropos.encryption.recipientFile or null) != null
          );
        message = ''
          services.katagrapho.encryption.required is true, but the epitropos
          proxy on this host is not configured to pass a recipient file: it is
          the process that execs katagrapho and supplies --recipient-file.
          Set services.epitropos.encryption.enable = true and
          services.epitropos.encryption.recipientFile (normally the same file
          as services.katagrapho.encryption.recipientFile), or set
          services.katagrapho.encryption.required = false.
        '';
      }
    ];

    # katagrapho reads /etc/katagrapho/config.toml if present. Only write it
    # when there is something to carry (plugin path); otherwise keep the
    # binary's built-in defaults, as before.
    environment.etc."katagrapho/config.toml" = mkIf needConfig {
      source = configFile;
      mode = "0444";
    };

    # katagrapho-verify is the whole point of the manifests and the chain, and
    # katagrapho-keygen is how an operator recovers from a key problem. Neither
    # was on any PATH, so verifying a recording meant digging a store path out
    # of the systemd unit.
    environment.systemPackages = [ cfg.package ];

    users.groups.${cfg.group} = {
      members = lib.optional
        (config.services.epitropos.enable or false)
        (config.services.epitropos.proxyUser or "session-proxy");
    };

    # Dedicated read-only group for daemons that need to ship or inspect
    # katagrapho state (e.g. epitropos-forward). Kept separate from
    # ${cfg.group} (ssh-sessions) so that shipping daemons don't inherit
    # every future perm attached to the recording-access group.
    users.groups.katagrapho-readers = { };

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      description = "Session recording file owner";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.storageDir} 2750 ${cfg.user} katagrapho-readers -"
      "d /var/lib/katagrapho 0750 ${cfg.user} katagrapho-readers -"
      # Re-chown the recording corpus to katagrapho-readers on every boot so
      # upgrades from a pre-readers-group install take effect without a manual
      # migration. Z, not z: z applies to the named path only, so the per-user
      # directories and the recordings themselves — the whole point of the
      # migration — were never touched.
      "Z ${cfg.storageDir} - ${cfg.user} katagrapho-readers -"
      # The chain state the readers group has to be able to verify. head.hash
      # is the truncation anchor; the recorder writes it 0640, and this keeps
      # pre-existing 0600 anchors from staying root-only after an upgrade.
      "Z /var/lib/katagrapho/head.hash 0640 ${cfg.user} katagrapho-readers -"
      "Z /var/lib/katagrapho/head.hash.log 0640 ${cfg.user} katagrapho-readers -"
      "Z /var/lib/katagrapho/signing.pub 0640 ${cfg.user} katagrapho-readers -"
    ];

    systemd.services.katagrapho-keygen = {
      description = "Generate or repair the katagrapho ed25519 signing key";
      wantedBy = [ "multi-user.target" ];
      # keygen hard-fails if it cannot chown the key to the recorder account,
      # so order it after user/group creation to avoid a spurious first-boot
      # failure.
      after = [
        "local-fs.target"
        "systemd-sysusers.service"
      ];
      # wantedBy alone does not make multi-user.target wait for a oneshot, and
      # sshd is a sibling of that target rather than ordered after this unit,
      # so without sshd here the first logins after boot race the key and get
      # recorded unsigned.
      before = [
        "multi-user.target"
        "sshd.service"
      ];
      # Deliberately NOT conditioned on the key's absence. keygen is
      # idempotent: it never overwrites a key, but it does re-assert ownership
      # and rebuild a missing signing.pub. Skipping the unit whenever the file
      # exists is what let a rename of services.katagrapho.user leave the key
      # owned by a dead uid — unreadable by the recorder, which then records
      # every session without a manifest.
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/katagrapho-keygen --user ${cfg.user} --group ${cfg.group}";
        User = "root";
        RemainAfterExit = true;
      };
    };

    security.wrappers.katagrapho = {
      source = lib.getExe cfg.package;
      owner = cfg.user;
      group = cfg.group;
      setuid = true;
      setgid = true;
      permissions = "u+rx,g+rx,o-rwx";
    };

    systemd.services.katagrapho-cleanup = mkIf cfg.logRotation.enable {
      description = "Clean up old session recordings";
      serviceConfig = {
        Type = "oneshot";
        # Recordings only. The manifest sidecars stay forever: they are ~1 KiB
        # each and they are the chain. Deleting them broke referential
        # integrity for every surviving manifest, so `katagrapho-verify
        # --check-chain` failed permanently on any host older than
        # maxAgeDays — with the default settings, on every host from day 91.
        # katagrapho-verify reports a recording whose sidecar outlived it as
        # pruned, distinct from a hash mismatch.
        # An allowlist, not "everything but manifests": epitropos drops its own
        # privilege sidecars in here and they are evidence too.
        ExecStart = ''${pkgs.findutils}/bin/find -P ${cfg.storageDir} -maxdepth 2 -type f -not -type l "(" -name "*.age" -o -name "*.cast" ")" -mtime +${toString cfg.logRotation.maxAgeDays} -delete'';
        User = cfg.user;
        Group = cfg.group;
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.storageDir ];
        ProtectHome = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        PrivateNetwork = true;
        PrivateDevices = true;
        MemoryDenyWriteExecute = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
      };
    };

    systemd.timers.katagrapho-cleanup = mkIf cfg.logRotation.enable {
      description = "Timer for session recording cleanup";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.logRotation.frequency;
        Persistent = true;
        RandomizedDelaySec = "6h";
      };
    };
  };
}
