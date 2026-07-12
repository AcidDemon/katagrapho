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
      default = "ssh-sessions";
      description = "Group that owns session recordings.";
    };

    user = mkOption {
      type = types.str;
      default = "session-writer";
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
        description = "Path to file containing age public key(s) for encrypting recordings.";
      };

      required = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether encryption is required. When true (default), katagrapho
          refuses to run without a recipient file. When false, unencrypted
          recordings are allowed.
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
    ];

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
      # Re-chown recording corpus group to katagrapho-readers on every
      # boot so upgrades from pre-Track-C installs take effect without
      # a manual migration.
      "z ${cfg.storageDir} 2750 ${cfg.user} katagrapho-readers -"
      "z /var/lib/katagrapho/head.hash.log 0640 ${cfg.user} katagrapho-readers -"
      "z /var/lib/katagrapho/signing.pub 0640 ${cfg.user} katagrapho-readers -"
    ];

    systemd.services.katagrapho-keygen = {
      description = "Generate katagrapho ed25519 signing key (first boot only)";
      wantedBy = [ "multi-user.target" ];
      # keygen hard-fails if it cannot chown the key to session-writer:ssh-sessions,
      # so order it after user/group creation to avoid a spurious first-boot failure.
      after = [
        "local-fs.target"
        "systemd-sysusers.service"
      ];
      unitConfig = {
        ConditionPathExists = "!/var/lib/katagrapho/signing.key";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/katagrapho-keygen";
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
        ExecStart = "${pkgs.findutils}/bin/find -P ${cfg.storageDir} -maxdepth 2 -type f -not -type l -mtime +${toString cfg.logRotation.maxAgeDays} -delete";
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
