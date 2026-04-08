// katagrapho-verify — audit tool for manifest sidecars.
//
// Included via #[path] to share the same modules as the main katagrapho
// binary without creating a library crate. The #[path] inclusion drags
// in items this binary doesn't use directly; suppress the resulting
// dead-code warnings at file scope.

#![allow(dead_code)]

#[path = "../src/error.rs"]
mod error;
#[path = "../src/signing.rs"]
mod signing;
#[path = "../src/manifest.rs"]
mod manifest;
#[path = "../src/verify.rs"]
mod verify;
#[path = "../src/chain.rs"]
#[allow(dead_code)]
mod chain;

use std::path::PathBuf;
use std::process::exit;

use crate::error::{EX_NOINPUT, EX_USAGE, KatagraphoError};

const EX_VERIFY_FAIL: i32 = 1;
#[allow(dead_code)]
const EX_CHUNK_MISMATCH: i32 = 2;
const EX_CHAIN_BROKEN: i32 = 3;
const EX_MANIFEST_MALFORMED: i32 = 4;

fn print_usage() {
    eprintln!(
        "Usage: katagrapho-verify [--check-chain] [--with-key <age-identity>] [--pub <pubkey>] <path>\n\
         \n\
         <path> may be a sidecar manifest or a directory of manifests.\n\
         \n\
         Exit codes:\n\
           0   verified\n\
           1   signature mismatch\n\
           2   chunk hash mismatch (requires --with-key; not yet implemented)\n\
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
    let mut with_key: Option<PathBuf> = None;
    let mut pub_path = PathBuf::from("/var/lib/katagrapho/signing.pub");

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
            "--with-key" if i + 1 < args.len() => {
                i += 1;
                with_key = Some(PathBuf::from(&args[i]));
            }
            "--pub" if i + 1 < args.len() => {
                i += 1;
                pub_path = PathBuf::from(&args[i]);
            }
            "--help" | "-h" => {
                print_usage();
                exit(0);
            }
            other if !other.starts_with('-') => {
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
        eprintln!("katagrapho-verify: pubkey not found at {}", pub_path.display());
        exit(EX_NOINPUT);
    }
    let pub_bytes = std::fs::read(&pub_path).unwrap_or_default();
    if pub_bytes.len() != 32 {
        eprintln!("katagrapho-verify: pubkey wrong length (expected 32 bytes)");
        exit(EX_MANIFEST_MALFORMED);
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);

    let result = if path.is_dir() {
        match verify::verify_recursive(&path, &pub_arr, check_chain) {
            Ok(r) => {
                println!(
                    "katagrapho-verify: {} manifests verified{}",
                    r.manifests_checked,
                    if r.chain_walked { " (chain ok)" } else { "" }
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else {
        verify::verify_single(&path, &pub_arr).map(|_| {
            println!("katagrapho-verify: ok");
        })
    };

    match result {
        Ok(()) => {
            if with_key.is_some() {
                eprintln!(
                    "katagrapho-verify: --with-key not yet implemented; chunk hashes \
                     are committed by the manifest signature already"
                );
            }
            exit(0);
        }
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
