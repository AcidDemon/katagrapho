// katagrapho-verify — audit tool for manifest sidecars.
//
// Included via #[path] to share the same modules as the main katagrapho
// binary without creating a library crate. The #[path] inclusion drags
// in items this binary doesn't use directly; suppress the resulting
// dead-code warnings at file scope.

#![allow(dead_code)]

#[path = "../src/chain.rs"]
#[allow(dead_code)]
mod chain;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/manifest.rs"]
mod manifest;
#[path = "../src/signing.rs"]
mod signing;
#[path = "../src/verify.rs"]
mod verify;

use std::path::PathBuf;
use std::process::exit;

use crate::error::{EX_NOINPUT, EX_USAGE, KatagraphoError};

const EX_VERIFY_FAIL: i32 = 1;
const EX_CHAIN_BROKEN: i32 = 3;
const EX_MANIFEST_MALFORMED: i32 = 4;

fn print_usage() {
    eprintln!(
        "Usage: katagrapho-verify [--check-chain] [--pub <pubkey>] [--chain-dir <dir>] <path>\n\
         \n\
         <path> may be a sidecar manifest or a directory of manifests.\n\
         --check-chain also anchors to <chain-dir>/head.hash to detect tail truncation.\n\
         A directory walk additionally reports recordings that have no manifest.\n\
         \n\
         Exit codes:\n\
           0   verified\n\
           1   signature mismatch, recording content mismatch, or unsigned recording\n\
           3   chain broken\n\
           4   manifest malformed\n\
           64  bad CLI args\n\
           66  path or pubkey missing"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut path: Option<PathBuf> = None;
    let mut check_chain = false;
    let mut pub_path = PathBuf::from("/var/lib/katagrapho/signing.pub");
    let mut chain_dir = PathBuf::from("/var/lib/katagrapho");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!(
                    "katagrapho-verify {} ({})",
                    env!("CARGO_PKG_VERSION"),
                    env!("KATAGRAPHO_GIT_COMMIT")
                );
                exit(0);
            }
            "--check-chain" => check_chain = true,
            "--pub" if i + 1 < args.len() => {
                i += 1;
                pub_path = PathBuf::from(&args[i]);
            }
            "--chain-dir" if i + 1 < args.len() => {
                i += 1;
                chain_dir = PathBuf::from(&args[i]);
            }
            "--help" | "-h" => {
                print_usage();
                exit(0);
            }
            // One path per run. Silently keeping the last of several means a
            // scripted "verify these three" reports success for one of them.
            other if !other.starts_with('-') => {
                if path.is_some() {
                    eprintln!("katagrapho-verify: only one <path> may be given");
                    exit(EX_USAGE);
                }
                path = Some(PathBuf::from(other));
            }
            other => {
                eprintln!("katagrapho-verify: unknown argument: {other}");
                print_usage();
                exit(EX_USAGE);
            }
        }
        i += 1;
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("katagrapho-verify: <path> required");
            print_usage();
            exit(EX_USAGE);
        }
    };

    if !pub_path.exists() {
        eprintln!(
            "katagrapho-verify: pubkey not found at {}",
            pub_path.display()
        );
        exit(EX_NOINPUT);
    }
    let pub_bytes = std::fs::read(&pub_path).unwrap_or_default();
    if pub_bytes.len() != 32 {
        eprintln!("katagrapho-verify: pubkey wrong length (expected 32 bytes)");
        exit(EX_MANIFEST_MALFORMED);
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);

    // Anchor chain verification to the persisted head so tail truncation (deletion
    // of the newest manifests) is detectable. read_head returns GENESIS when no
    // head.hash exists yet, which verify_recursive treats as "nothing to anchor".
    let expected_head = if check_chain {
        let paths = chain::ChainPaths::under(&chain_dir);

        // The log is its own chain, signed line by line. Verify it before the
        // manifests: it is the only record that survives the manifests being
        // deleted, so it is the thing an attacker rewrites first.
        let log = match chain::verify_log(&paths, &pub_arr) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("katagrapho-verify: {e}");
                exit(EX_CHAIN_BROKEN);
            }
        };
        println!(
            "katagrapho-verify: chain log: {} signed line(s) verified{}",
            log.signed_lines,
            if log.legacy_lines > 0 {
                format!(
                    ", {} unsigned legacy line(s) before them (written by a build without log \
                     signing; unverifiable)",
                    log.legacy_lines
                )
            } else {
                String::new()
            }
        );

        let head = match chain::read_head(&paths) {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!(
                    "katagrapho-verify: warning: cannot read chain head ({e}); \
                     tail-truncation check skipped"
                );
                None
            }
        };

        // head.hash and the log are written under the same lock in the same
        // transaction, so they cannot legitimately disagree. If they do, one
        // of the two was edited afterwards.
        if let (Some(h), Some(tip)) = (head.as_deref(), log.tip_manifest_hash())
            && h != tip
        {
            eprintln!(
                "katagrapho-verify: head.hash ({h}) does not match the last signed log entry \
                 ({tip}) — one of the two was rewritten"
            );
            exit(EX_CHAIN_BROKEN);
        }
        head
    } else {
        None
    };

    let result = if path.is_dir() {
        match verify::verify_recursive(&path, &pub_arr, check_chain, expected_head.as_deref()) {
            Ok(r) => {
                println!(
                    "katagrapho-verify: {} manifests verified{}{}",
                    r.manifests_checked,
                    if r.chain_walked { " (chain ok)" } else { "" },
                    if r.recordings_pruned > 0 {
                        format!(
                            ", {} recording(s) pruned by retention (sidecar kept, content \
                             not re-hashable)",
                            r.recordings_pruned
                        )
                    } else {
                        String::new()
                    }
                );
                // Availability-first recording means a missing sidecar is a real
                // event, not a quirk: report every one and fail, or the operator
                // learns nothing from a green run.
                if r.unsigned_recordings.is_empty() {
                    Ok(())
                } else {
                    for p in &r.unsigned_recordings {
                        eprintln!("katagrapho-verify: UNSIGNED recording {}", p.display());
                    }
                    Err(KatagraphoError::Verify(format!(
                        "{} recording(s) have no manifest — they were written without \
                         integrity (signing key unreadable at record time?)",
                        r.unsigned_recordings.len()
                    )))
                }
            }
            Err(e) => Err(e),
        }
    } else {
        verify::verify_single(&path, &pub_arr).map(|c| match c {
            verify::Content::Verified => println!("katagrapho-verify: ok"),
            verify::Content::Pruned => println!(
                "katagrapho-verify: ok (signature valid; recording pruned by retention, \
                 content not re-hashable)"
            ),
        })
    };

    match result {
        Ok(()) => exit(0),
        Err(KatagraphoError::Verify(msg)) => {
            eprintln!("katagrapho-verify: {msg}");
            exit(EX_VERIFY_FAIL);
        }
        Err(KatagraphoError::Chain(msg)) => {
            eprintln!("katagrapho-verify: {msg}");
            exit(EX_CHAIN_BROKEN);
        }
        Err(KatagraphoError::Manifest(msg)) => {
            eprintln!("katagrapho-verify: {msg}");
            exit(EX_MANIFEST_MALFORMED);
        }
        Err(e) => {
            eprintln!("katagrapho-verify: {e}");
            exit(e.exit_code());
        }
    }
}
