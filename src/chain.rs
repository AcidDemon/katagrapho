//! Per-host manifest chain. Atomically advances `head.hash`, appends
//! to `head.hash.log`, all under flock to serialize concurrent writers.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::KatagraphoError;
use crate::manifest::GENESIS_PREV;

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
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| KatagraphoError::Chain(format!("open head tmp: {e}")))?;
    f.write_all(hex_hash.as_bytes())
        .map_err(|e| KatagraphoError::Chain(format!("write head: {e}")))?;
    f.sync_all()
        .map_err(|e| KatagraphoError::Chain(format!("fsync head: {e}")))?;
    drop(f);
    fs::rename(&tmp, &paths.head)
        .map_err(|e| KatagraphoError::Chain(format!("rename head: {e}")))?;
    Ok(())
}

#[allow(dead_code)]
pub fn append_log(
    paths: &ChainPaths,
    iso_ts: &str,
    user: &str,
    session_id: &str,
    part: u32,
    hex_hash: &str,
) -> Result<(), KatagraphoError> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(&paths.log)
        .map_err(|e| KatagraphoError::Chain(format!("open log: {e}")))?;
    let line = format!("{iso_ts} {user} {session_id} {part} {hex_hash}\n");
    f.write_all(line.as_bytes())
        .map_err(|e| KatagraphoError::Chain(format!("write log: {e}")))?;
    f.sync_all()
        .map_err(|e| KatagraphoError::Chain(format!("fsync log: {e}")))?;
    Ok(())
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

    #[test]
    fn append_log_creates_file_and_appends() {
        let dir = tempdir().unwrap();
        let paths = ChainPaths::under(dir.path());
        append_log(
            &paths,
            "2026-04-07T12:00:00Z",
            "alice",
            "abc",
            0,
            &"a".repeat(64),
        )
        .unwrap();
        append_log(
            &paths,
            "2026-04-07T12:01:00Z",
            "bob",
            "def",
            1,
            &"b".repeat(64),
        )
        .unwrap();
        let content = fs::read_to_string(&paths.log).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("alice abc 0"));
        assert!(content.contains("bob def 1"));
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
