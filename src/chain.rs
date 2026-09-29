//! Per-host manifest chain. Atomically advances `head.hash`, appends
//! to `head.hash.log`, all under flock to serialize concurrent writers.
//!
//! The log is a second, independent chain. Each line carries the hash of the
//! line before it and an ed25519 signature over its own digest, so the log is
//! tamper-evident on its own terms: it detects an edited line, a removed line
//! and a reordered line even if every manifest on the host has been deleted.
//! Without that it was plain text that nothing signed and nothing read, so
//! anyone who could write to the chain directory could rewrite the history of
//! the host and leave no trace.
//!
//! Line format, eight whitespace-separated fields:
//!
//! ```text
//! <iso_ts> <user> <session_id> <part> <manifest_hash> <log_prev> <log_hash> <sig>
//! ```
//!
//! `log_hash` is the SHA-256 of the first six fields joined with NUL, and
//! `sig` is base64 of an ed25519 signature over those 32 bytes. Older hosts
//! wrote five-field lines with no hash and no signature; those verify as
//! legacy and are only accepted as a contiguous prefix, so the log cannot be
//! downgraded line by line to escape verification.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::KatagraphoError;
use crate::manifest::{GENESIS_PREV, base64_decode, base64_encode};
use crate::signing::{KeyPair, verify_with_pub};

/// Number of fields in a signed log line, and in a pre-signing legacy line.
const LOG_FIELDS_SIGNED: usize = 8;
const LOG_FIELDS_LEGACY: usize = 5;

pub struct ChainPaths {
    pub head: PathBuf,
    pub log: PathBuf,
    pub lock: PathBuf,
}

impl ChainPaths {
    pub fn under(dir: &Path) -> Self {
        Self {
            head: dir.join("head.hash"),
            log: dir.join("head.hash.log"),
            lock: dir.join("head.hash.lock"),
        }
    }
}

/// RAII guard for the chain flock.
pub struct ChainLock {
    file: fs::File,
}

impl ChainLock {
    #[allow(dead_code)]
    pub fn acquire(paths: &ChainPaths) -> Result<Self, KatagraphoError> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&paths.lock)
            .map_err(|e| KatagraphoError::Chain(format!("open lock: {e}")))?;
        let fd = file.as_raw_fd();
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc != 0 {
            return Err(KatagraphoError::Chain(format!(
                "flock: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { file })
    }
}

impl Drop for ChainLock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub fn read_head(paths: &ChainPaths) -> Result<String, KatagraphoError> {
    if !paths.head.exists() {
        return Ok(GENESIS_PREV.to_string());
    }
    let s = fs::read_to_string(&paths.head)
        .map_err(|e| KatagraphoError::Chain(format!("read head: {e}")))?;
    let trimmed = s.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KatagraphoError::Chain(format!(
            "head.hash not 64 hex chars: {trimmed:?}"
        )));
    }
    Ok(trimmed.to_string())
}

/// fsync a directory so a rename into it survives a crash. Without this the
/// new head.hash can be lost while the recording and its sidecar survive,
/// leaving the chain anchored at a hash nothing holds — a fork the verifier
/// then reports as truncation.
fn fsync_dir(dir: &Path) -> Result<(), KatagraphoError> {
    let d = fs::File::open(dir)
        .map_err(|e| KatagraphoError::Chain(format!("open {} for fsync: {e}", dir.display())))?;
    d.sync_all()
        .map_err(|e| KatagraphoError::Chain(format!("fsync {}: {e}", dir.display())))
}

pub fn write_head(paths: &ChainPaths, hex_hash: &str) -> Result<(), KatagraphoError> {
    if hex_hash.len() != 64 {
        return Err(KatagraphoError::Chain(
            "write_head: hash must be 64 hex chars".to_string(),
        ));
    }
    let tmp = paths.head.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        // 0640, like head.hash.log: the tip is the anchor that makes tail
        // truncation detectable, so an auditor in the readers group has to be
        // able to read it. At 0600 only root could, and `katagrapho-verify
        // --check-chain` silently skipped the check for everyone else.
        .mode(0o640)
        .open(&tmp)
        .map_err(|e| KatagraphoError::Chain(format!("open head tmp: {e}")))?;
    f.write_all(hex_hash.as_bytes())
        .map_err(|e| KatagraphoError::Chain(format!("write head: {e}")))?;
    f.sync_all()
        .map_err(|e| KatagraphoError::Chain(format!("fsync head: {e}")))?;
    drop(f);
    fs::rename(&tmp, &paths.head)
        .map_err(|e| KatagraphoError::Chain(format!("rename head: {e}")))?;
    if let Some(dir) = paths.head.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}

/// Digest of a log line: the first six fields joined with NUL. NUL, not a
/// space, so no field value can imitate a field boundary.
fn log_digest(
    iso_ts: &str,
    user: &str,
    session_id: &str,
    part: u32,
    manifest_hash: &str,
    log_prev: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    for field in [
        iso_ts,
        user,
        session_id,
        &part.to_string(),
        manifest_hash,
        log_prev,
    ] {
        h.update(field.as_bytes());
        h.update([0u8]);
    }
    h.finalize().into()
}

/// A field that could contain whitespace or NUL would let a single append
/// write what reads back as several lines, which is a way to forge chain
/// history from a username.
fn reject_unsafe_field(label: &str, value: &str) -> Result<(), KatagraphoError> {
    if value.is_empty() {
        return Err(KatagraphoError::Chain(format!("log {label} is empty")));
    }
    if value.contains(|c: char| c.is_whitespace() || c == '\0') {
        return Err(KatagraphoError::Chain(format!(
            "log {label} contains whitespace or NUL: {value:?}"
        )));
    }
    Ok(())
}

/// The `log_hash` of the last line, or GENESIS when the log is new. Callers
/// hold the chain lock, so this cannot race another appender.
fn read_log_tip(paths: &ChainPaths) -> Result<String, KatagraphoError> {
    let content = match fs::read_to_string(&paths.log) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(GENESIS_PREV.to_string()),
        Err(e) => return Err(KatagraphoError::Chain(format!("read log: {e}"))),
    };
    match content.lines().rev().find(|l| !l.trim().is_empty()) {
        None => Ok(GENESIS_PREV.to_string()),
        Some(last) => {
            let fields: Vec<&str> = last.split_whitespace().collect();
            match fields.len() {
                // Legacy tail: the new line starts a fresh log chain from
                // genesis. The legacy prefix stays readable and is reported as
                // unverifiable rather than as tampering.
                LOG_FIELDS_LEGACY => Ok(GENESIS_PREV.to_string()),
                LOG_FIELDS_SIGNED => Ok(fields[6].to_string()),
                n => Err(KatagraphoError::Chain(format!(
                    "last log line has {n} fields, expected {LOG_FIELDS_LEGACY} or {LOG_FIELDS_SIGNED}"
                ))),
            }
        }
    }
}

// ponytail: the log is never rotated. A signed line is about 250 bytes, so
// RLIMIT_FSIZE (512 MiB + slack) is reached after roughly two million parts,
// and the write then fails with EFBIG rather than killing the process, because
// SIGXFSZ is ignored. Rotating needs a carry-over line that signs the previous
// file's tip hash so the chain survives the split; add that when a host is
// plausibly heading for a million sessions.
#[allow(dead_code)]
pub fn append_log(
    paths: &ChainPaths,
    iso_ts: &str,
    user: &str,
    session_id: &str,
    part: u32,
    hex_hash: &str,
    key: &KeyPair,
) -> Result<(), KatagraphoError> {
    reject_unsafe_field("timestamp", iso_ts)?;
    reject_unsafe_field("user", user)?;
    reject_unsafe_field("session_id", session_id)?;
    reject_unsafe_field("manifest_hash", hex_hash)?;

    let log_prev = read_log_tip(paths)?;
    let digest = log_digest(iso_ts, user, session_id, part, hex_hash, &log_prev);
    let sig = base64_encode(&key.sign(&digest));
    let line = format!(
        "{iso_ts} {user} {session_id} {part} {hex_hash} {log_prev} {} {sig}\n",
        hex::encode(digest)
    );

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(&paths.log)
        .map_err(|e| KatagraphoError::Chain(format!("open log: {e}")))?;
    f.write_all(line.as_bytes())
        .map_err(|e| KatagraphoError::Chain(format!("write log: {e}")))?;
    f.sync_all()
        .map_err(|e| KatagraphoError::Chain(format!("fsync log: {e}")))?;
    if let Some(dir) = paths.log.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}

/// One parsed log line. Used by katagrapho-verify, not the recorder.
#[derive(Debug)]
#[allow(dead_code)]
pub struct LogEntry {
    pub iso_ts: String,
    pub user: String,
    pub session_id: String,
    pub part: u32,
    pub manifest_hash: String,
    pub log_hash: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct LogVerification {
    pub entries: Vec<LogEntry>,
    /// Lines written before the log was signed. Unverifiable, not tampered.
    pub legacy_lines: usize,
    pub signed_lines: usize,
}

#[allow(dead_code)]
impl LogVerification {
    /// The newest manifest hash the log claims. `head.hash` must agree with
    /// it; if it does not, one of the two was rewritten.
    pub fn tip_manifest_hash(&self) -> Option<&str> {
        self.entries.last().map(|e| e.manifest_hash.as_str())
    }
}

/// Verify the log as a chain in its own right: every signed line's digest is
/// recomputed, its signature checked, and its `log_prev` matched against the
/// previous signed line. A missing or reordered line breaks the linkage even
/// though each individual signature would still verify.
#[allow(dead_code)]
pub fn verify_log(
    paths: &ChainPaths,
    pub_bytes: &[u8; 32],
) -> Result<LogVerification, KatagraphoError> {
    let content = match fs::read_to_string(&paths.log) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LogVerification {
                entries: Vec::new(),
                legacy_lines: 0,
                signed_lines: 0,
            });
        }
        Err(e) => return Err(KatagraphoError::Chain(format!("read log: {e}"))),
    };

    let mut out = LogVerification {
        entries: Vec::new(),
        legacy_lines: 0,
        signed_lines: 0,
    };
    let mut expected_prev = GENESIS_PREV.to_string();

    for (idx, raw) in content.lines().enumerate() {
        let lineno = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = raw.split_whitespace().collect();
        let part = |s: &str| -> Result<u32, KatagraphoError> {
            s.parse().map_err(|_| {
                KatagraphoError::Chain(format!("log line {lineno}: part is not a number"))
            })
        };

        match f.len() {
            LOG_FIELDS_LEGACY => {
                // Only as a contiguous prefix. Once a signed line has been
                // seen, an unsigned line is an attempt to drop the signature
                // rather than an old record.
                if out.signed_lines > 0 {
                    return Err(KatagraphoError::Chain(format!(
                        "log line {lineno} is unsigned but follows signed lines — the log was \
                         downgraded"
                    )));
                }
                out.legacy_lines += 1;
                out.entries.push(LogEntry {
                    iso_ts: f[0].to_string(),
                    user: f[1].to_string(),
                    session_id: f[2].to_string(),
                    part: part(f[3])?,
                    manifest_hash: f[4].to_string(),
                    log_hash: None,
                });
            }
            LOG_FIELDS_SIGNED => {
                let (iso_ts, user, session_id, manifest_hash, log_prev, log_hash, sig_b64) =
                    (f[0], f[1], f[2], f[4], f[5], f[6], f[7]);
                let part = part(f[3])?;

                let digest = log_digest(iso_ts, user, session_id, part, manifest_hash, log_prev);
                if hex::encode(digest) != log_hash {
                    return Err(KatagraphoError::Chain(format!(
                        "log line {lineno}: log_hash does not match the line contents"
                    )));
                }
                let sig_bytes = base64_decode(sig_b64)
                    .map_err(|e| KatagraphoError::Chain(format!("log line {lineno}: {e}")))?;
                let sig: [u8; 64] = sig_bytes.try_into().map_err(|_| {
                    KatagraphoError::Chain(format!("log line {lineno}: signature is not 64 bytes"))
                })?;
                verify_with_pub(pub_bytes, &digest, &sig).map_err(|e| {
                    KatagraphoError::Chain(format!("log line {lineno}: bad signature ({e})"))
                })?;
                if log_prev != expected_prev {
                    return Err(KatagraphoError::Chain(format!(
                        "log line {lineno}: log_prev {log_prev} does not link to the previous \
                         line ({expected_prev}) — a line was removed, reordered or inserted"
                    )));
                }
                expected_prev = log_hash.to_string();
                out.signed_lines += 1;
                out.entries.push(LogEntry {
                    iso_ts: iso_ts.to_string(),
                    user: user.to_string(),
                    session_id: session_id.to_string(),
                    part,
                    manifest_hash: manifest_hash.to_string(),
                    log_hash: Some(log_hash.to_string()),
                });
            }
            n => {
                return Err(KatagraphoError::Chain(format!(
                    "log line {lineno} has {n} fields, expected {LOG_FIELDS_LEGACY} or \
                     {LOG_FIELDS_SIGNED}"
                )));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_head_returns_genesis_when_missing() {
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        assert_eq!(read_head(&paths).unwrap(), GENESIS_PREV);
    }

    #[test]
    fn write_then_read_head_round_trip() {
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        let hash = "ab".repeat(32);
        write_head(&paths, &hash).unwrap();
        assert_eq!(read_head(&paths).unwrap(), hash);
    }

    #[test]
    fn head_is_group_readable() {
        // The readers group verifies the chain; at 0600 only root could, and
        // the tail-truncation check was skipped for everyone else.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        // Same umask the recorder sets at startup, so the assertion describes
        // the deployed mode rather than the developer's shell.
        let prev = unsafe { libc::umask(0o027) };
        write_head(&paths, &"cd".repeat(32)).unwrap();
        unsafe { libc::umask(prev) };
        let mode = fs::metadata(&paths.head).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "head.hash must be group-readable");
    }

    #[test]
    fn write_head_rejects_short_hash() {
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        assert!(write_head(&paths, "deadbeef").is_err());
    }

    #[test]
    fn read_head_rejects_corrupt_file() {
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        fs::write(&paths.head, "not hex").unwrap();
        assert!(read_head(&paths).is_err());
    }

    fn key(dir: &Path) -> KeyPair {
        KeyPair::generate_to(&dir.join("k.key"), &dir.join("k.pub")).unwrap()
    }

    /// Append two entries and return (paths, keypair).
    fn two_entry_log(dir: &Path) -> (ChainPaths, KeyPair) {
        let paths = ChainPaths::under(dir);
        let kp = key(dir);
        append_log(
            &paths,
            "2026-04-07T12:00:00Z",
            "alice",
            "abc",
            0,
            &"a".repeat(64),
            &kp,
        )
        .unwrap();
        append_log(
            &paths,
            "2026-04-07T12:01:00Z",
            "bob",
            "def",
            1,
            &"b".repeat(64),
            &kp,
        )
        .unwrap();
        (paths, kp)
    }

    fn rewrite(paths: &ChainPaths, lines: &[String]) {
        fs::write(&paths.log, lines.join("\n") + "\n").unwrap();
    }

    fn lines_of(paths: &ChainPaths) -> Vec<String> {
        fs::read_to_string(&paths.log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn append_log_creates_file_and_appends() {
        let dir = tempdir().unwrap();
        let (paths, _kp) = two_entry_log(dir.path());
        let content = fs::read_to_string(&paths.log).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("alice abc 0"));
        assert!(content.contains("bob def 1"));
    }

    #[test]
    fn verify_log_accepts_what_append_wrote() {
        let dir = tempdir().unwrap();
        let (paths, kp) = two_entry_log(dir.path());
        let v = verify_log(&paths, &kp.public_bytes()).unwrap();
        assert_eq!(v.signed_lines, 2);
        assert_eq!(v.legacy_lines, 0);
        assert_eq!(v.tip_manifest_hash(), Some("b".repeat(64).as_str()));
    }

    #[test]
    fn verify_log_detects_an_edited_field() {
        let dir = tempdir().unwrap();
        let (paths, kp) = two_entry_log(dir.path());
        let edited: Vec<String> = lines_of(&paths)
            .iter()
            .map(|l| l.replace(" bob ", " mallory "))
            .collect();
        rewrite(&paths, &edited);
        let err = verify_log(&paths, &kp.public_bytes()).unwrap_err();
        assert!(format!("{err}").contains("log_hash"), "got {err}");
    }

    #[test]
    fn verify_log_detects_a_removed_line() {
        // Each signature still verifies on its own. Only the log_prev linkage
        // shows that something between them is gone.
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        let kp = key(dir.path());
        for (i, user) in ["alice", "bob", "carol"].iter().enumerate() {
            append_log(
                &paths,
                "2026-04-07T12:00:00Z",
                user,
                "s",
                i as u32,
                &"c".repeat(64),
                &kp,
            )
            .unwrap();
        }
        let all = lines_of(&paths);
        rewrite(&paths, &[all[0].clone(), all[2].clone()]);
        let err = verify_log(&paths, &kp.public_bytes()).unwrap_err();
        assert!(format!("{err}").contains("log_prev"), "got {err}");
    }

    #[test]
    fn verify_log_detects_reordering() {
        let dir = tempdir().unwrap();
        let (paths, kp) = two_entry_log(dir.path());
        let all = lines_of(&paths);
        rewrite(&paths, &[all[1].clone(), all[0].clone()]);
        assert!(verify_log(&paths, &kp.public_bytes()).is_err());
    }

    #[test]
    fn verify_log_rejects_a_foreign_signature() {
        let dir = tempdir().unwrap();
        let (paths, _kp) = two_entry_log(dir.path());
        let other =
            KeyPair::generate_to(&dir.path().join("other.key"), &dir.path().join("other.pub"))
                .unwrap();
        let err = verify_log(&paths, &other.public_bytes()).unwrap_err();
        assert!(format!("{err}").contains("signature"), "got {err}");
    }

    #[test]
    fn legacy_lines_verify_as_a_prefix_but_cannot_follow_signed_ones() {
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        let kp = key(dir.path());
        // A log written by an older build.
        let legacy = format!("2026-04-07T11:00:00Z old s 0 {}", "d".repeat(64));
        fs::write(&paths.log, format!("{legacy}\n")).unwrap();
        // This build appends on top of it.
        append_log(
            &paths,
            "2026-04-07T12:00:00Z",
            "alice",
            "abc",
            0,
            &"a".repeat(64),
            &kp,
        )
        .unwrap();

        let v = verify_log(&paths, &kp.public_bytes()).unwrap();
        assert_eq!(v.legacy_lines, 1);
        assert_eq!(v.signed_lines, 1);

        // Appending an unsigned line after a signed one is a downgrade, not
        // an old record.
        let mut all = lines_of(&paths);
        all.push(legacy);
        rewrite(&paths, &all);
        let err = verify_log(&paths, &kp.public_bytes()).unwrap_err();
        assert!(format!("{err}").contains("downgraded"), "got {err}");
    }

    #[test]
    fn concurrent_appends_produce_one_unbroken_log() {
        // Concurrent logins are the normal case on a bastion, and the module
        // doc claims flock serialises writers, but nothing exercised more than
        // one. The failure this guards is a lost update: two writers that read
        // the same tip both link to it, so the log holds two lines claiming the
        // same predecessor and the chain the whole design rests on has forked.
        //
        // flock is held per open file description, so separate acquires from
        // one process contend exactly as separate processes do.
        use std::sync::Arc;

        const WRITERS: usize = 8;
        let dir = tempdir().unwrap();
        let paths = Arc::new(ChainPaths::under(dir.path()));
        let kp = Arc::new(key(dir.path()));

        let handles: Vec<_> = (0..WRITERS)
            .map(|i| {
                let paths = Arc::clone(&paths);
                let kp = Arc::clone(&kp);
                std::thread::spawn(move || {
                    // The same sequence write_manifest_and_advance performs:
                    // one lock around reading the tip and advancing both files.
                    let _lock = ChainLock::acquire(&paths).unwrap();
                    let manifest_hash = format!("{:064x}", i + 1);
                    write_head(&paths, &manifest_hash).unwrap();
                    append_log(
                        &paths,
                        "2026-04-07T12:00:00Z",
                        "u",
                        &format!("s{i}"),
                        0,
                        &manifest_hash,
                        &kp,
                    )
                    .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().expect("a writer panicked");
        }

        // verify_log walks log_prev, so a lost update cannot pass here: the
        // second writer to link to a reused tip breaks the linkage.
        let v = verify_log(&paths, &kp.public_bytes()).unwrap();
        assert_eq!(v.signed_lines, WRITERS, "every writer must appear once");
        assert_eq!(v.legacy_lines, 0);

        // Whoever appended last must also own head.hash: the two are advanced
        // under one lock and may not drift apart.
        assert_eq!(
            read_head(&paths).unwrap(),
            v.tip_manifest_hash().unwrap(),
            "head.hash and the log tip disagree"
        );

        // All eight manifest hashes are present exactly once, so no writer's
        // entry was overwritten.
        let seen: std::collections::HashSet<&str> =
            v.entries.iter().map(|e| e.manifest_hash.as_str()).collect();
        assert_eq!(seen.len(), WRITERS);
    }

    #[test]
    fn append_log_refuses_fields_that_could_forge_a_line() {
        // A username containing a newline would let one append write what
        // reads back as two log lines.
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        let kp = key(dir.path());
        let err = append_log(
            &paths,
            "2026-04-07T12:00:00Z",
            "alice\n2026-04-07T12:00:01Z forged s 0 ffff",
            "abc",
            0,
            &"a".repeat(64),
            &kp,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("whitespace"), "got {err}");
        assert!(!paths.log.exists(), "nothing may be written on rejection");
    }

    #[test]
    fn lock_acquire_release_round_trip() {
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        {
            let _g = ChainLock::acquire(&paths).unwrap();
        }
        let _g2 = ChainLock::acquire(&paths).unwrap();
    }
}
