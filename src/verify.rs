//! High-level verification orchestration for the katagrapho-verify tool.

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::KatagraphoError;
use crate::manifest::{GENESIS_PREV, Manifest};

pub struct VerifyResult {
    pub manifests_checked: usize,
    pub chain_walked: bool,
}

/// SHA-256 of a file, hex-encoded. Streamed in 64 KiB blocks.
fn sha256_file(path: &Path) -> Result<String, KatagraphoError> {
    let mut f = fs::File::open(path)
        .map_err(|e| KatagraphoError::Verify(format!("open recording {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|e| {
            KatagraphoError::Verify(format!("read recording {}: {e}", path.display()))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Re-hash the recording file a manifest describes and confirm it matches the
/// signed `recording_sha256`. This is what proves the stored recording itself
/// was not altered — the manifest signature alone only proves the manifest is
/// authentic, not that the `.age` file beside it still matches. The recording
/// lives next to its sidecar under the manifest's own `recording_file` basename.
fn verify_recording_content(sidecar: &Path, m: &Manifest) -> Result<(), KatagraphoError> {
    let dir = sidecar.parent().unwrap_or_else(|| Path::new("."));
    let recording = dir.join(&m.recording_file);
    let actual = sha256_file(&recording)?;
    if actual != m.recording_sha256 {
        return Err(KatagraphoError::Verify(format!(
            "recording {} content does not match manifest: signed {}, on-disk {}",
            recording.display(),
            m.recording_sha256,
            actual
        )));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn verify_single(sidecar: &Path, pub_bytes: &[u8; 32]) -> Result<(), KatagraphoError> {
    let m = Manifest::load_from(sidecar)?;
    m.verify(pub_bytes)?;
    verify_recording_content(sidecar, &m)
}

/// Verify every manifest under `dir`: signature, then that the recording file it
/// describes still hashes to the signed value. With `check_chain`, also verify
/// referential integrity (every non-genesis `prev_manifest_hash` is present) and,
/// when `expected_head` is supplied, that the persisted chain tip is still present
/// — the only way to detect tail truncation (deletion of the newest recordings).
#[allow(dead_code)]
pub fn verify_recursive(
    dir: &Path,
    pub_bytes: &[u8; 32],
    check_chain: bool,
    expected_head: Option<&str>,
) -> Result<VerifyResult, KatagraphoError> {
    let mut entries: Vec<(PathBuf, Manifest)> = Vec::new();
    walk_collect(dir, &mut entries)?;
    let total = entries.len();
    for (sidecar, m) in &entries {
        m.verify(pub_bytes)?;
        verify_recording_content(sidecar, m)?;
    }
    if check_chain {
        let mut by_hash: HashMap<&str, &Manifest> = HashMap::new();
        for (_, m) in &entries {
            by_hash.insert(m.this_manifest_hash.as_str(), m);
        }
        for (_, m) in &entries {
            if m.prev_manifest_hash == GENESIS_PREV {
                continue;
            }
            if !by_hash.contains_key(m.prev_manifest_hash.as_str()) {
                return Err(KatagraphoError::Chain(format!(
                    "manifest {} has prev_manifest_hash {} not present in set",
                    m.session_id, m.prev_manifest_hash
                )));
            }
        }
        // Anchor to the authoritative chain tip. Referential integrity alone
        // cannot catch deletion of the newest manifests — the remaining set is
        // still internally consistent. If head.hash names a tip we no longer
        // hold, the tail was truncated.
        if let Some(head) =
            expected_head.filter(|h| *h != GENESIS_PREV && !by_hash.contains_key(*h))
        {
            return Err(KatagraphoError::Chain(format!(
                "chain tip {head} (from head.hash) is missing — recordings were truncated"
            )));
        }
    }
    Ok(VerifyResult {
        manifests_checked: total,
        chain_walked: check_chain,
    })
}

fn walk_collect(dir: &Path, out: &mut Vec<(PathBuf, Manifest)>) -> Result<(), KatagraphoError> {
    let read = fs::read_dir(dir)
        .map_err(|e| KatagraphoError::Verify(format!("read_dir {}: {e}", dir.display())))?;
    for entry in read {
        let entry = entry.map_err(|e| KatagraphoError::Verify(format!("dir entry: {e}")))?;
        // Use the dir entry's own file type — it does not follow symlinks, so a
        // symlinked directory cannot redirect the walk or create a recursion loop.
        let ft = entry
            .file_type()
            .map_err(|e| KatagraphoError::Verify(format!("file type: {e}")))?;
        let path = entry.path();
        if ft.is_dir() {
            walk_collect(&path, out)?;
        } else if ft.is_file()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".manifest.json"))
                .unwrap_or(false)
        {
            let m = Manifest::load_from(&path)?;
            out.push((path, m));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::MANIFEST_VERSION;
    use crate::signing::KeyPair;
    use tempfile::tempdir;

    fn sha_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    /// Write a recording file and return a manifest whose signed
    /// `recording_sha256`/`recording_file` match it. Caller signs + writes it.
    fn make_with_recording(dir: &Path, prev: &str, sid: &str, content: &[u8]) -> Manifest {
        let recording_file = format!("{sid}.kgv1.age");
        fs::write(dir.join(&recording_file), content).unwrap();
        Manifest {
            v: MANIFEST_VERSION.to_string(),
            session_id: sid.to_string(),
            part: 0,
            user: "u".to_string(),
            host: "h".to_string(),
            boot_id: "b".to_string(),
            audit_session_id: None,
            started: 0.0,
            ended: 1.0,
            katagrapho_version: "0".to_string(),
            katagrapho_commit: "0".to_string(),
            epitropos_version: "0".to_string(),
            epitropos_commit: "0".to_string(),
            recording_file,
            recording_size: content.len() as u64,
            recording_sha256: sha_hex(content),
            chunks: vec![],
            end_reason: "eof".to_string(),
            exit_code: 0,
            prev_manifest_hash: prev.to_string(),
            this_manifest_hash: String::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    fn key(dir: &Path) -> KeyPair {
        KeyPair::generate_to(&dir.join("k.key"), &dir.join("k.pub")).unwrap()
    }

    #[test]
    fn verify_recursive_walks_chain_clean() {
        let dir = tempdir().unwrap();
        let kp = key(dir.path());

        let mut m1 = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"session one bytes");
        m1.sign(&kp).unwrap();
        m1.write_to(&dir.path().join("s1.manifest.json")).unwrap();

        let mut m2 = make_with_recording(
            dir.path(),
            &m1.this_manifest_hash,
            "s2",
            b"session two bytes",
        );
        m2.sign(&kp).unwrap();
        m2.write_to(&dir.path().join("s2.manifest.json")).unwrap();

        let result = verify_recursive(
            dir.path(),
            &kp.public_bytes(),
            true,
            Some(&m2.this_manifest_hash),
        )
        .unwrap();
        assert_eq!(result.manifests_checked, 2);
        assert!(result.chain_walked);
    }

    #[test]
    fn verify_recursive_detects_broken_chain() {
        let dir = tempdir().unwrap();
        let kp = key(dir.path());

        let mut m1 = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"one");
        m1.sign(&kp).unwrap();
        m1.write_to(&dir.path().join("s1.manifest.json")).unwrap();

        let mut m2 = make_with_recording(dir.path(), &"f".repeat(64), "s2", b"two");
        m2.sign(&kp).unwrap();
        m2.write_to(&dir.path().join("s2.manifest.json")).unwrap();

        assert!(verify_recursive(dir.path(), &kp.public_bytes(), true, None).is_err());
    }

    #[test]
    fn verify_single_detects_tampered_field() {
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"content");
        m.sign(&kp).unwrap();
        let path = dir.path().join("s1.manifest.json");
        m.write_to(&path).unwrap();

        // Tamper the on-disk sidecar's user field (mode 0444 → make writable).
        let tampered = fs::read_to_string(&path)
            .unwrap()
            .replace("\"user\": \"u\"", "\"user\": \"mallory\"");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        fs::write(&path, tampered).unwrap();

        assert!(verify_single(&path, &kp.public_bytes()).is_err());
    }

    #[test]
    fn verify_detects_tampered_recording_content() {
        // A byte-flip in the stored recording must be caught even though the
        // manifest signature still verifies against itself.
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"original recording");
        m.sign(&kp).unwrap();
        let sidecar = dir.path().join("s1.manifest.json");
        m.write_to(&sidecar).unwrap();

        // Manifest alone still verifies.
        assert!(m.verify(&kp.public_bytes()).is_ok());

        // Flip the recording content on disk.
        fs::write(dir.path().join("s1.kgv1.age"), b"TAMPERED recording").unwrap();

        // verify_single (signature + content) must now fail.
        let err = verify_single(&sidecar, &kp.public_bytes());
        assert!(err.is_err(), "recording tamper must be detected");
        assert!(format!("{}", err.err().unwrap()).contains("does not match"));
    }

    #[test]
    fn verify_detects_tail_truncation_via_head_anchor() {
        // Deleting the newest manifest leaves a still-consistent shorter chain;
        // only anchoring to head.hash catches it.
        let dir = tempdir().unwrap();
        let kp = key(dir.path());

        let mut m1 = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"one");
        m1.sign(&kp).unwrap();
        m1.write_to(&dir.path().join("s1.manifest.json")).unwrap();

        let mut m2 = make_with_recording(dir.path(), &m1.this_manifest_hash, "s2", b"two");
        m2.sign(&kp).unwrap();
        m2.write_to(&dir.path().join("s2.manifest.json")).unwrap();

        let head = m2.this_manifest_hash.clone();

        // Delete the newest manifest + its recording (the truncation).
        fs::remove_file(dir.path().join("s2.manifest.json")).unwrap();
        fs::remove_file(dir.path().join("s2.kgv1.age")).unwrap();

        // Without the anchor, the remaining single manifest looks consistent.
        assert!(verify_recursive(dir.path(), &kp.public_bytes(), true, None).is_ok());
        // With the anchor, the missing tip is flagged.
        let err = verify_recursive(dir.path(), &kp.public_bytes(), true, Some(&head));
        assert!(
            err.is_err(),
            "tail truncation must be detected via head anchor"
        );
        assert!(format!("{}", err.err().unwrap()).contains("truncated"));
    }
}
