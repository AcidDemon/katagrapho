# katagrapho

Setuid+setgid binary for tamper-proof session recording with age encryption. Reads asciicinema data from stdin, encrypts it, and writes to files that the recorded user **cannot modify or delete**.

Named after the Greek *katagrapho* (to write down/record) — the process that commits every session to disk.

## How it works

`katagrapho` reads stdin and writes to `/var/log/ssh-sessions/<user>/<session-id>.cast.age`. It runs setuid as a dedicated `session-writer` user and setgid as `ssh-sessions`. Files are created mode `0440` — the recorded user has no ownership and cannot `chmod`, overwrite, or unlink them.

Key properties:

- **Streaming age encryption** via the `age` crate — data is encrypted as it arrives, never buffered in plaintext
- **Encryption enforced by default** — refuses to run without `--recipient-file` (explicit `--no-encrypt` required for plaintext)
- **Partial file preservation** — interrupted recordings are kept as evidence, not deleted
- **Termination markers** — writes an asciicinema `"x"` event on abnormal interruption
- **Race-free file creation** via `openat()` with `O_CREAT|O_EXCL|O_NOFOLLOW`
- **Username from kernel** — resolved from real UID via `getpwuid()`, not caller arguments
- **Environment sanitized** — `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc. stripped at startup
- **512 MiB per-session size limit**
- **Full RELRO, PIE, overflow checks**

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
            # encryption.required = true;  # default
            # logRotation.maxAgeDays = 90;  # default
          };
        }
      ];
    };
  };
}
```

This creates the `session-writer` user, `ssh-sessions` group, storage directory, setuid/setgid wrapper at `/run/wrappers/bin/katagrapho`, and a weekly cleanup timer.

## Usage

Designed to be spawned by [epitropos](https://github.com/AcidDemon/epitropos) (the PTY-proxy), but can also be used standalone:

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
| **[epitropos](https://github.com/AcidDemon/epitropos)** | PTY proxy — PAM-triggered, owns the terminal, generates asciicinema v2 |
| **katagrapho** | Storage writer — encrypts with age, writes tamper-proof files |

IPC is a stdin pipe. `epitropos` spawns `katagrapho` as a child process and pipes the asciicinema stream to it.

## Permission model

```
/var/log/ssh-sessions/              session-writer:ssh-sessions  2770
/var/log/ssh-sessions/<user>/       session-writer:ssh-sessions  0750
/var/log/ssh-sessions/<user>/*.age  session-writer:ssh-sessions  0440
/run/wrappers/bin/katagrapho        session-writer:ssh-sessions  setuid+setgid
```

The recorded user owns nothing in this chain. Only `root` and members of `ssh-sessions` can read the recordings.

## Building from source

```sh
# With Nix
nix build

# With Cargo
cargo build --release
```

Requires Rust >= 1.85 (edition 2024).

## Dependencies

- `libc` — POSIX syscalls (`openat`, `getpwuid`, `umask`)
- `age` — streaming age encryption (pure Rust)

## License

MIT
