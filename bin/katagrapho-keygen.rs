// katagrapho-keygen — ed25519 signing key generator and repair step.
//
// Generates /var/lib/katagrapho/signing.key (mode 0400) and signing.pub
// (mode 0444), owned by the recorder account named by --user/--group.
// Idempotent, so it is safe on every boot: an existing key is never
// overwritten, but its ownership is re-asserted and a missing public half is
// rebuilt from it.

#![allow(dead_code)]

#[path = "../src/error.rs"]
mod error;
#[path = "../src/kata_config.rs"]
mod kata_config;
#[path = "../src/signing.rs"]
mod signing;

use std::ffi::CString;
use std::path::{Path, PathBuf};
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

    // Read the same config the recorder reads. These paths are configurable
    // (signing.key_path / signing.pub_path), and keygen used to ignore that
    // and hardcode /var/lib/katagrapho: on a host that moved them, keygen
    // wrote a key the recorder never looked at, and the recorder then ran
    // key-less, recording every session without a manifest.
    let config_path = PathBuf::from(kata_config::CONFIG_PATH);
    let cfg = if config_path.exists() {
        match kata_config::KataConfig::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "katagrapho-keygen: cannot read {}: {e}",
                    config_path.display()
                );
                exit(78); // EX_CONFIG
            }
        }
    } else {
        kata_config::KataConfig::default()
    };
    let key_path = cfg.signing.key_path.clone();
    let pub_path = cfg.signing.pub_path.clone();

    // Never overwrite a key — that would orphan every manifest already signed
    // with it — but do re-assert ownership. Renaming the recorder account
    // leaves the key owned by a uid that no longer exists, the recorder cannot
    // read it, and recording continues WITHOUT manifests. Repairing that here
    // is what makes this unit safe to run on every boot instead of once.
    if key_path.exists() {
        // A crash between the two renames in generate_to can leave the key
        // present and the public half missing, which disables verification
        // host-wide with no way back. Rebuild it from the key.
        if !pub_path.exists() {
            match signing::KeyPair::load(&key_path, &pub_path) {
                Ok(kp) => {
                    if let Err(e) = kp.write_public_to(&pub_path) {
                        eprintln!("katagrapho-keygen: cannot rebuild signing.pub: {e}");
                        exit(70);
                    }
                    eprintln!(
                        "katagrapho-keygen: rebuilt missing signing.pub for key_id={}",
                        kp.key_id_hex()
                    );
                }
                Err(e) => {
                    eprintln!("katagrapho-keygen: signing.key present but unusable: {e}");
                    exit(70);
                }
            }
        }
        if !chown_key_material(&key_path, &pub_path, &owner_user, &owner_group) {
            exit(73); // EX_CANTCREAT
        }
        eprintln!(
            "katagrapho-keygen: {} already exists; ownership re-asserted as \
             {owner_user}:{owner_group}",
            key_path.display()
        );
        exit(0);
    }

    match signing::KeyPair::generate_to(&key_path, &pub_path) {
        Ok(kp) => {
            eprintln!("katagrapho-keygen: generated key_id={}", kp.key_id_hex());
            if !chown_key_material(&key_path, &pub_path, &owner_user, &owner_group) {
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

/// Chown the key material to the recorder's user:group. This MUST succeed: the
/// key is written 0400, so if it stays owned by anyone else the recording
/// process cannot read it and every recording is written WITHOUT integrity.
/// Fail loudly rather than leave that silent hole.
fn chown_key_material(key_path: &Path, pub_path: &Path, user: &str, group: &str) -> bool {
    let ok = unsafe {
        let user_c = CString::new(user).unwrap();
        let group_c = CString::new(group).unwrap();
        let pw = libc::getpwnam(user_c.as_ptr());
        let gr = libc::getgrnam(group_c.as_ptr());
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
    if !ok {
        eprintln!(
            "katagrapho-keygen: FAILED to chown {} to {user}:{group} — the key would be \
             unreadable by the recording process and recordings written WITHOUT integrity. \
             Ensure the user and group exist, then re-run.",
            key_path.display()
        );
    }
    ok
}
