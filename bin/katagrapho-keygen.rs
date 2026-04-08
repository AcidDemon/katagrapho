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
    for arg in std::env::args().skip(1) {
        if arg == "--version" || arg == "-V" {
            println!(
                "katagrapho-keygen {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("KATAGRAPHO_GIT_COMMIT")
            );
            exit(0);
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
            // Chown to session-writer:ssh-sessions. Silent on failure —
            // the systemd unit runs as root, so failing chown means
            // the target user/group doesn't exist and the operator
            // will see the ownership mismatch on the first recording.
            unsafe {
                let user = CString::new("session-writer").unwrap();
                let group = CString::new("ssh-sessions").unwrap();
                let pw = libc::getpwnam(user.as_ptr());
                let gr = libc::getgrnam(group.as_ptr());
                if !pw.is_null() && !gr.is_null() {
                    let key_c = CString::new(key_path.to_str().unwrap()).unwrap();
                    let pub_c = CString::new(pub_path.to_str().unwrap()).unwrap();
                    libc::chown(key_c.as_ptr(), (*pw).pw_uid, (*gr).gr_gid);
                    libc::chown(pub_c.as_ptr(), (*pw).pw_uid, (*gr).gr_gid);
                }
            }
            exit(0);
        }
        Err(e) => {
            eprintln!("katagrapho-keygen: {e}");
            exit(70);
        }
    }
}
