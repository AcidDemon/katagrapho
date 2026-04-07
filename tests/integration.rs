//! CLI-level smoke tests for katagrapho. These verify argv handling,
//! exit codes, and the --version output without needing access to a
//! real STORAGE_DIR (which the binary refuses to write to as a non-
//! privileged user).
//!
//! End-to-end recording verification lives in the NixOS VM test in
//! the epitropos repo (which spawns katagrapho in a real privileged
//! environment).

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_flag_prints_and_exits_zero() {
    Command::cargo_bin("katagrapho")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("katagrapho "));
}

#[test]
fn short_version_flag_works() {
    Command::cargo_bin("katagrapho")
        .unwrap()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("katagrapho "));
}

#[test]
fn unknown_flag_exits_64() {
    Command::cargo_bin("katagrapho")
        .unwrap()
        .arg("--bogus")
        .assert()
        .failure()
        .code(64)
        .stderr(predicate::str::contains("unknown argument"));
}

#[test]
fn missing_session_id_exits_64() {
    Command::cargo_bin("katagrapho")
        .unwrap()
        .arg("--no-encrypt")
        .assert()
        .failure()
        .code(64)
        .stderr(predicate::str::contains("--session-id"));
}

#[test]
fn invalid_session_id_chars_exit_65() {
    Command::cargo_bin("katagrapho")
        .unwrap()
        .args(["--session-id", "bad/id", "--no-encrypt"])
        .assert()
        .failure()
        .code(65)
        .stderr(predicate::str::contains("invalid character"));
}

#[test]
fn mutually_exclusive_flags_exit_64() {
    Command::cargo_bin("katagrapho")
        .unwrap()
        .args([
            "--session-id",
            "ok",
            "--no-encrypt",
            "--recipient-file",
            "/etc/age/recipients",
        ])
        .assert()
        .failure()
        .code(64)
        .stderr(predicate::str::contains("mutually exclusive"));
}

#[test]
fn missing_recipient_file_without_no_encrypt_exits_64() {
    Command::cargo_bin("katagrapho")
        .unwrap()
        .args(["--session-id", "ok"])
        .assert()
        .failure()
        .code(64)
        .stderr(predicate::str::contains("--recipient-file is required"));
}
