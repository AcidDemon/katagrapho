{
  description = "katagrapho: setuid+setgid binary for tamper-proof session recording with age encryption";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
      ...
    }:
    let
      # Linux-only: setgid/setuid, O_NOFOLLOW, /var/log paths.
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

      # edition = "2024" requires Rust >= 1.85.
      rustToolchainFor = pkgs: pkgs.rust-bin.stable.latest.minimal;

      # One source of truth; it used to be spelled out in three places and had
      # already drifted from the tree.
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;

      # cleanCargoSource strips .git, so build.rs cannot find the revision.
      # Hand it in, or every signed manifest claims commit "unknown".
      gitCommit = self.shortRev or self.dirtyShortRev or "unknown";

      mkKatagrapho =
        pkgs:
        let
          rustToolchain = rustToolchainFor pkgs;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;

          commonArgs = {
            inherit src version;
            pname = "katagrapho";
            strictDeps = true;
            KATAGRAPHO_GIT_COMMIT = gitCommit;

            # Security hardening via linker flags. panic=abort is NOT set here:
            # [profile.release] in Cargo.toml already aborts for the binaries,
            # and cargo drops that setting for test targets by itself — as a
            # RUSTFLAG it applied to the test harness too, which is the only
            # reason the package build had to skip its own tests.
            RUSTFLAGS = "-C link-arg=-Wl,-z,relro,-z,now";
          };

          cargoArtifacts = craneLib.buildDepsOnly (
            commonArgs // { doCheck = false; }
          );
        in
        craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;

            meta = {
              description = "katagrapho: setuid+setgid binary for tamper-proof session recording with age encryption";
              license = pkgs.lib.licenses.mit;
              platforms = pkgs.lib.platforms.linux;
              mainProgram = "katagrapho";
            };
          }
        );
    in
    {
      packages = forAllSystems (system: rec {
        katagrapho = mkKatagrapho (pkgsFor system);
        default = katagrapho;
      });

      nixosModules = {
        default = self.nixosModules.katagrapho;
        katagrapho = import ./nixos-module.nix self;
      };

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          # minimal lacks rustfmt/clippy, which the fmt and clippy checks need.
          rustToolchain = (rustToolchainFor pkgs).override {
            extensions = [
              "rustfmt"
              "clippy"
            ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;
          checkArgs = {
            inherit src version;
            pname = "katagrapho";
            strictDeps = true;
            KATAGRAPHO_GIT_COMMIT = gitCommit;
          };
          checkArtifacts = craneLib.buildDepsOnly checkArgs;
        in
        {
          package = self.packages.${system}.default;

          clippy = craneLib.cargoClippy (
            checkArgs
            // {
              cargoArtifacts = checkArtifacts;
              # --all-targets, or the tests themselves are never linted.
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );

          fmt = craneLib.cargoFmt { inherit src version; pname = "katagrapho"; };

          tests = craneLib.cargoTest (checkArgs // { cargoArtifacts = checkArtifacts; });

          # checkArgs deliberately omits the package's RUSTFLAGS, so nothing
          # else here would notice if the hardening flags were dropped.
          hardening =
            pkgs.runCommand "katagrapho-hardening" { nativeBuildInputs = [ pkgs.binutils ]; }
              ''
                exe=${self.packages.${system}.katagrapho}/bin/katagrapho
                ${pkgs.binutils}/bin/readelf -dW "$exe" | grep -q BIND_NOW
                ${pkgs.binutils}/bin/readelf -lW "$exe" | grep -q GNU_RELRO
                touch $out
              '';

          # Eval-only, sub-second, no builder. The account-rename class of bug
          # lives entirely in this module, and `nix flake check` could not see
          # it: nothing here ever evaluated the module.
          module-eval =
            let
              mk =
                extra:
                nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.katagrapho
                    extra
                    {
                      boot.loader.grub.enable = false;
                      fileSystems."/" = {
                        device = "none";
                        fsType = "tmpfs";
                      };
                      system.stateVersion = "25.05";
                    }
                  ];
                };
              broken = s: builtins.filter (a: !a.assertion) s.config.assertions;
              ok = mk {
                services.katagrapho = {
                  enable = true;
                  encryption.recipientFile = "/etc/age/recipients.txt";
                };
              };
              # required = true with no recipient file must fail the build.
              bad = mk { services.katagrapho.enable = true; };
              wrapper = ok.config.security.wrappers.katagrapho;
              keygen = ok.config.systemd.services.katagrapho-keygen;
              rules = ok.config.systemd.tmpfiles.rules;
            in
            assert broken ok == [ ];
            assert builtins.length (broken bad) == 1;
            assert wrapper.setuid && wrapper.setgid;
            assert wrapper.owner == "katagrapho";
            # keygen must be idempotent-by-default (no skip-if-exists) and must
            # complete before anything that can start a recorded session.
            assert !(keygen.unitConfig or { } ? ConditionPathExists);
            assert builtins.elem "sshd.service" keygen.before;
            assert builtins.elem "multi-user.target" keygen.before;
            # The corpus migration has to recurse, or it does nothing.
            assert builtins.any (r: nixpkgs.lib.hasPrefix "Z /var/log/ssh-sessions" r) rules;
            # Retention must not delete manifests: that is the chain.
            assert nixpkgs.lib.hasInfix "-name \"*.age\""
              ok.config.systemd.services.katagrapho-cleanup.serviceConfig.ExecStart;
            pkgs.runCommand "katagrapho-module-eval" { } "touch $out";
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = (pkgs.rust-bin.stable.latest.default).override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
            ];
          };
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [ rustToolchain ];
          };
        }
      );
    };
}
