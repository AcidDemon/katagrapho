// katagrapho-keygen — first-boot ed25519 signing key generator.
//
// Generates /var/lib/katagrapho/signing.key (mode 0400) and signing.pub
// (mode 0444) owned by session-writer:ssh-sessions. Refuses to overwrite
// an existing key.

#![allow(dead_code)]

#[path = "../src/error.rs"]
mod error;
#[path = "../src/signing.rs"]
mod signing;

use std::ffi::CString;
use std::path::PathBuf;
use std::process::exit;

fn main() {
    // The signing key is chowned to the account that runs the recorder. Names
    // are passed in (the NixOS module supplies services.katagrapho.user/group)
    // rather than hardcoded, so the operator can rename the writer account.
    let mut owner_user = String::from("katagrapho");
    let mut owner_group = String::from("katagrapho");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => {
                println!(
                    "katagrapho-keygen {} ({})",
                    env!("CARGO_PKG_VERSION"),
                    env!("KATAGRAPHO_GIT_COMMIT")
                );
                exit(0);
            }
            "--user" => match args.next() {
                Some(v) => owner_user = v,
                None => {
                    eprintln!("katagrapho-keygen: --user requires a value");
                    exit(64); // EX_USAGE
                }
            },
            "--group" => match args.next() {
                Some(v) => owner_group = v,
                None => {
                    eprintln!("katagrapho-keygen: --group requires a value");
                    exit(64);
                }
            },
            other => {
                eprintln!("katagrapho-keygen: unknown argument: {other}");
                exit(64);
            }
        }
    }

    let key_path = PathBuf::from("/var/lib/katagrapho/signing.key");
    let pub_path = PathBuf::from("/var/lib/katagrapho/signing.pub");

    if key_path.exists() {
        eprintln!(
            "katagrapho-keygen: {} already exists; refusing to overwrite",
            key_path.display()
        );
        exit(0);
    }

    match signing::KeyPair::generate_to(&key_path, &pub_path) {
        Ok(kp) => {
            eprintln!("katagrapho-keygen: generated key_id={}", kp.key_id_hex());
            // Chown to the recorder's user:group. This MUST succeed: the key is
            // written 0400, so if it stays root-owned the recording process
            // cannot read it and every recording is written WITHOUT integrity.
            // Fail loudly rather than leave that silent hole.
            let chown_ok = unsafe {
                let user = CString::new(owner_user.as_str()).unwrap();
                let group = CString::new(owner_group.as_str()).unwrap();
                let pw = libc::getpwnam(user.as_ptr());
                let gr = libc::getgrnam(group.as_ptr());
                if pw.is_null() || gr.is_null() {
                    false
                } else {
                    let key_c = CString::new(key_path.to_str().unwrap()).unwrap();
                    let pub_c = CString::new(pub_path.to_str().unwrap()).unwrap();
                    let r1 = libc::chown(key_c.as_ptr(), (*pw).pw_uid, (*gr).gr_gid);
                    let r2 = libc::chown(pub_c.as_ptr(), (*pw).pw_uid, (*gr).gr_gid);
                    r1 == 0 && r2 == 0
                }
            };
            if !chown_ok {
                eprintln!(
                    "katagrapho-keygen: FAILED to chown {} to {owner_user}:{owner_group} — \
                     the key would be unreadable by the recording process and recordings \
                     written WITHOUT integrity. Ensure the user and group exist, then re-run.",
                    key_path.display()
                );
                exit(73); // EX_CANTCREAT
            }
            exit(0);
        }
        Err(e) => {
            eprintln!("katagrapho-keygen: {e}");
            exit(70);
        }
    }
}
