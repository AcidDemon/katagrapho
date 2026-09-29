//! High-level verification orchestration for the katagrapho-verify tool.

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::KatagraphoError;
use crate::manifest::{GENESIS_PREV, Manifest};

#[derive(Debug)]
pub struct VerifyResult {
    pub manifests_checked: usize,
    pub chain_walked: bool,
    /// Manifests whose recording is no longer on disk. Retention deletes
    /// recordings but keeps their sidecars, so this is expected on an aged
    /// host: signature and chain still verify, only the content re-hash
    /// cannot run. Distinguishing it from a hash mismatch is the whole point.
    pub recordings_pruned: usize,
    /// Recordings with no sidecar beside them. katagrapho is
    /// availability-first: if the signing key is unreadable it records anyway,
    /// unsigned. A manifest-driven walk cannot see those files at all, so
    /// collect them explicitly — an unsigned recording is a finding, not a gap.
    pub unsigned_recordings: Vec<PathBuf>,
}

/// Outcome of re-hashing the recording a manifest describes.
#[derive(Debug, PartialEq, Eq)]
pub enum Content {
    Verified,
    Pruned,
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

/// Locate the recording a sidecar belongs to.
///
/// A sidecar is always written as `<recording>.manifest.json`, so the recording's
/// real name is the sidecar path minus that suffix. That is preferred over the
/// manifest's own `recording_file`, because a signed field is a record of the
/// original name, not a path: the collector renames recordings on ingest
/// (`.cast.age` → `.kgv1.age`) and the signed field keeps saying `.cast.age`,
/// which is why verification used to fail on every collector-side copy.
/// `recording_file` stays as the fallback, reduced to its basename so a manifest
/// can never point the walk outside the sidecar's own directory.
fn recording_for(sidecar: &Path, m: &Manifest) -> Option<PathBuf> {
    let derived = sidecar
        .to_str()
        .and_then(|s| s.strip_suffix(".manifest.json"))
        .map(PathBuf::from);
    if let Some(p) = derived.filter(|p| p.exists()) {
        return Some(p);
    }
    let dir = sidecar.parent().unwrap_or_else(|| Path::new("."));
    let beside = dir.join(Path::new(&m.recording_file).file_name()?);
    beside.exists().then_some(beside)
}

/// Re-hash the recording file a manifest describes and confirm it matches the
/// signed `recording_sha256`. This is what proves the stored recording itself
/// was not altered — the manifest signature alone only proves the manifest is
/// authentic, not that the `.age` file beside it still matches.
fn verify_recording_content(sidecar: &Path, m: &Manifest) -> Result<Content, KatagraphoError> {
    let Some(recording) = recording_for(sidecar, m) else {
        return Ok(Content::Pruned);
    };
    verify_recording_hash(&recording, m)?;
    Ok(Content::Verified)
}

fn verify_recording_hash(recording: &Path, m: &Manifest) -> Result<(), KatagraphoError> {
    let actual = sha256_file(recording)?;
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
pub fn verify_single(sidecar: &Path, pub_bytes: &[u8; 32]) -> Result<Content, KatagraphoError> {
    let m = Manifest::load_from(sidecar)?;
    m.verify(pub_bytes)?;
    verify_recording_content(sidecar, &m)
}

/// Verify every manifest under `dir`: signature, then that the recording file it
/// describes still hashes to the signed value. With `check_chain`, also verify
/// referential integrity (every non-genesis `prev_manifest_hash` is present) and,
/// when `expected_head` is supplied, that the persisted chain tip is still present
/// — the only way to detect tail truncation (deletion of the newest recordings).
///
/// Recordings with no sidecar are reported in the result rather than ignored:
/// the walk is manifest-driven, so an unsigned recording would otherwise be
/// invisible to exactly the tool meant to find it.
#[allow(dead_code)]
pub fn verify_recursive(
    dir: &Path,
    pub_bytes: &[u8; 32],
    check_chain: bool,
    expected_head: Option<&str>,
) -> Result<VerifyResult, KatagraphoError> {
    let mut entries: Vec<(PathBuf, Manifest)> = Vec::new();
    let mut recordings: Vec<PathBuf> = Vec::new();
    walk_collect(dir, &mut entries, &mut recordings)?;
    let total = entries.len();
    let mut pruned = 0usize;
    let mut signed: HashSet<PathBuf> = HashSet::new();
    for (sidecar, m) in &entries {
        m.verify(pub_bytes)?;
        match recording_for(sidecar, m) {
            Some(recording) => {
                verify_recording_hash(&recording, m)?;
                signed.insert(recording);
            }
            None => pruned += 1,
        }
    }
    let unsigned: Vec<PathBuf> = recordings
        .into_iter()
        .filter(|r| !signed.contains(r))
        .collect();
    if check_chain {
        check_single_chain(&entries, expected_head)?;
    }
    Ok(VerifyResult {
        manifests_checked: total,
        chain_walked: check_chain,
        recordings_pruned: pruned,
        unsigned_recordings: unsigned,
    })
}

/// Confirm the manifests form ONE chain, not merely a set in which every
/// `prev_manifest_hash` happens to be present.
///
/// Referential integrity alone accepts a fork (two manifests claiming the same
/// predecessor), a second genesis, and a detached branch running alongside the
/// real history. Each of those is what a rewrite looks like: append a parallel
/// run of manifests, signed with the host's own key, and the old check passed.
/// So the set has to be walked as a single path from one tip back to one
/// genesis, and every manifest has to lie on it.
fn check_single_chain(
    entries: &[(PathBuf, Manifest)],
    expected_head: Option<&str>,
) -> Result<(), KatagraphoError> {
    if entries.is_empty() {
        // Nothing to walk. A head.hash naming a tip is still a truncation.
        if let Some(head) = expected_head.filter(|h| *h != GENESIS_PREV) {
            return Err(KatagraphoError::Chain(format!(
                "chain tip {head} (from head.hash) is missing — recordings were truncated"
            )));
        }
        return Ok(());
    }

    let mut by_hash: HashMap<&str, &Manifest> = HashMap::new();
    for (path, m) in entries {
        if let Some(dup) = by_hash.insert(m.this_manifest_hash.as_str(), m) {
            return Err(KatagraphoError::Chain(format!(
                "two manifests share this_manifest_hash {}: sessions {} and {} ({})",
                m.this_manifest_hash,
                dup.session_id,
                m.session_id,
                path.display()
            )));
        }
    }

    // One predecessor may have at most one successor, and there may be at
    // most one genesis.
    let mut child_of: HashMap<&str, &Manifest> = HashMap::new();
    let mut genesis: Option<&Manifest> = None;
    for (_, m) in entries {
        if m.prev_manifest_hash == GENESIS_PREV {
            if let Some(first) = genesis {
                return Err(KatagraphoError::Chain(format!(
                    "two genesis manifests: sessions {} and {} — the chain was restarted or a \
                     parallel history was grafted on",
                    first.session_id, m.session_id
                )));
            }
            genesis = Some(m);
            continue;
        }
        if !by_hash.contains_key(m.prev_manifest_hash.as_str()) {
            return Err(KatagraphoError::Chain(format!(
                "manifest {} has prev_manifest_hash {} not present in set",
                m.session_id, m.prev_manifest_hash
            )));
        }
        if let Some(sibling) = child_of.insert(m.prev_manifest_hash.as_str(), m) {
            return Err(KatagraphoError::Chain(format!(
                "chain forks at {}: sessions {} and {} both follow it",
                m.prev_manifest_hash, sibling.session_id, m.session_id
            )));
        }
    }
    let genesis = genesis.ok_or_else(|| {
        KatagraphoError::Chain(
            "no genesis manifest: every manifest names a predecessor, so the start of the chain \
             is missing"
                .to_string(),
        )
    })?;

    // The tip is the one manifest nothing follows. head.hash, when readable,
    // is the authority on which tip that should be: referential integrity
    // cannot notice that the newest manifests were deleted, because what is
    // left is still internally consistent.
    let tip = match expected_head.filter(|h| *h != GENESIS_PREV) {
        Some(head) => *by_hash.get(head).ok_or_else(|| {
            KatagraphoError::Chain(format!(
                "chain tip {head} (from head.hash) is missing — recordings were truncated"
            ))
        })?,
        None => {
            let mut tips = entries
                .iter()
                .map(|(_, m)| m)
                .filter(|m| !child_of.contains_key(m.this_manifest_hash.as_str()));
            let first = tips.next().ok_or_else(|| {
                KatagraphoError::Chain(
                    "no chain tip: every manifest is followed by another, which means the chain \
                     contains a cycle"
                        .to_string(),
                )
            })?;
            if let Some(second) = tips.next() {
                return Err(KatagraphoError::Chain(format!(
                    "two chain tips: sessions {} and {} — the set holds more than one history",
                    first.session_id, second.session_id
                )));
            }
            first
        }
    };

    // Walk tip to genesis. Every manifest must be on that path; anything left
    // over is a branch that does not belong to this host's history.
    let mut walked = 0usize;
    let mut cursor = tip;
    loop {
        walked += 1;
        if walked > entries.len() {
            return Err(KatagraphoError::Chain(
                "chain walk exceeded the manifest count — the chain contains a cycle".to_string(),
            ));
        }
        if cursor.this_manifest_hash == genesis.this_manifest_hash {
            break;
        }
        cursor = by_hash
            .get(cursor.prev_manifest_hash.as_str())
            .copied()
            .ok_or_else(|| {
                KatagraphoError::Chain(format!(
                    "chain walk broke at {}: predecessor {} is missing",
                    cursor.session_id, cursor.prev_manifest_hash
                ))
            })?;
    }
    if walked != entries.len() {
        return Err(KatagraphoError::Chain(format!(
            "{} manifests are not on the chain from genesis to the tip ({walked} of {} walked) — \
             an orphan branch is present",
            entries.len() - walked,
            entries.len()
        )));
    }
    Ok(())
}

/// True for a file that is a recording rather than a sidecar or a stray note.
/// katagrapho writes `.cast.age` (or `.cast` with --no-encrypt); the collector
/// stores the same bytes as `.kgv1.age`.
fn is_recording(name: &str) -> bool {
    (name.ends_with(".age") || name.ends_with(".cast")) && !name.ends_with(".manifest.json")
}

fn walk_collect(
    dir: &Path,
    out: &mut Vec<(PathBuf, Manifest)>,
    recordings: &mut Vec<PathBuf>,
) -> Result<(), KatagraphoError> {
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
            walk_collect(&path, out, recordings)?;
        } else if ft.is_file() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name.ends_with(".manifest.json") {
                let m = Manifest::load_from(&path)?;
                out.push((path, m));
            } else if is_recording(name) {
                recordings.push(path);
            }
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

    /// Sign `m` and write it as `<sid>.manifest.json`.
    fn place(dir: &Path, kp: &KeyPair, m: &mut Manifest, sid: &str) {
        m.sign(kp).unwrap();
        m.write_to(&dir.join(format!("{sid}.manifest.json")))
            .unwrap();
    }

    #[test]
    fn chain_rejects_a_fork() {
        // Two manifests claiming the same predecessor. Referential integrity
        // is satisfied, so the old check passed this.
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m1 = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"one");
        place(dir.path(), &kp, &mut m1, "s1");
        let mut a = make_with_recording(dir.path(), &m1.this_manifest_hash, "s2a", b"two-a");
        place(dir.path(), &kp, &mut a, "s2a");
        let mut b = make_with_recording(dir.path(), &m1.this_manifest_hash, "s2b", b"two-b");
        place(dir.path(), &kp, &mut b, "s2b");

        let err = verify_recursive(dir.path(), &kp.public_bytes(), true, None).unwrap_err();
        assert!(format!("{err}").contains("forks"), "got {err}");
    }

    #[test]
    fn chain_rejects_a_second_genesis() {
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m1 = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"one");
        place(dir.path(), &kp, &mut m1, "s1");
        let mut m2 = make_with_recording(dir.path(), GENESIS_PREV, "s2", b"two");
        place(dir.path(), &kp, &mut m2, "s2");

        let err = verify_recursive(dir.path(), &kp.public_bytes(), true, None).unwrap_err();
        assert!(format!("{err}").contains("genesis"), "got {err}");
    }

    #[test]
    fn chain_rejects_an_orphan_branch_alongside_the_real_history() {
        // A parallel run signed with the host's own key, anchored to the real
        // genesis but not on the path to the tip head.hash names.
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m1 = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"one");
        place(dir.path(), &kp, &mut m1, "s1");
        let mut m2 = make_with_recording(dir.path(), &m1.this_manifest_hash, "s2", b"two");
        place(dir.path(), &kp, &mut m2, "s2");
        // Branch off s1 as well, which makes s1 a fork point.
        let mut orphan = make_with_recording(dir.path(), &m1.this_manifest_hash, "sx", b"orphan");
        place(dir.path(), &kp, &mut orphan, "sx");

        let err = verify_recursive(
            dir.path(),
            &kp.public_bytes(),
            true,
            Some(&m2.this_manifest_hash),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("forks") || msg.contains("orphan"), "got {msg}");
    }

    #[test]
    fn chain_rejects_a_duplicate_manifest_hash() {
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"one");
        m.sign(&kp).unwrap();
        m.write_to(&dir.path().join("s1.manifest.json")).unwrap();
        // The same manifest filed twice, next to a second copy of its
        // recording so the content check still passes.
        fs::write(dir.path().join("copy.kgv1.age"), b"one").unwrap();
        m.write_to(&dir.path().join("copy.kgv1.age.manifest.json"))
            .unwrap();

        let err = verify_recursive(dir.path(), &kp.public_bytes(), true, None).unwrap_err();
        assert!(
            format!("{err}").contains("share this_manifest_hash"),
            "got {err}"
        );
    }

    #[test]
    fn verifies_a_recording_the_collector_renamed() {
        // The collector stores katagrapho's bytes as .kgv1.age while the signed
        // recording_file keeps saying .cast.age. Resolving the path from the
        // sidecar name is what makes an off-host copy verifiable at all.
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let content = b"shipped bytes";
        let mut m = make_with_recording(dir.path(), GENESIS_PREV, "s1", content);
        fs::remove_file(dir.path().join("s1.kgv1.age")).unwrap();
        m.recording_file = "s1.part0.cast.age".to_string(); // the name on the recorder
        m.sign(&kp).unwrap();

        let sidecar = dir.path().join("s1.part0.kgv1.age.manifest.json");
        fs::write(dir.path().join("s1.part0.kgv1.age"), content).unwrap();
        m.write_to(&sidecar).unwrap();

        assert_eq!(
            verify_single(&sidecar, &kp.public_bytes()).unwrap(),
            Content::Verified
        );
    }

    #[test]
    fn pruned_recording_is_not_a_tamper() {
        // Retention deletes recordings and keeps sidecars. That must stay
        // verifiable: a missing recording is reported, never reported as a
        // hash mismatch, and the chain still walks.
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"aged out");
        m.sign(&kp).unwrap();
        m.write_to(&dir.path().join("s1.manifest.json")).unwrap();
        fs::remove_file(dir.path().join("s1.kgv1.age")).unwrap();

        let r = verify_recursive(
            dir.path(),
            &kp.public_bytes(),
            true,
            Some(&m.this_manifest_hash),
        )
        .unwrap();
        assert_eq!(r.manifests_checked, 1);
        assert_eq!(r.recordings_pruned, 1);
        assert!(r.unsigned_recordings.is_empty());
    }

    #[test]
    fn unsigned_recording_is_reported() {
        // katagrapho records without a manifest when the signing key is
        // unreadable. A manifest-driven walk cannot see that file, so the walk
        // has to look for recordings too.
        let dir = tempdir().unwrap();
        let kp = key(dir.path());
        let mut m = make_with_recording(dir.path(), GENESIS_PREV, "s1", b"signed");
        m.sign(&kp).unwrap();
        m.write_to(&dir.path().join("s1.manifest.json")).unwrap();
        fs::write(dir.path().join("s2.cast.age"), b"no sidecar").unwrap();

        let r = verify_recursive(dir.path(), &kp.public_bytes(), false, None).unwrap();
        assert_eq!(r.manifests_checked, 1);
        assert_eq!(r.unsigned_recordings.len(), 1);
        assert!(
            r.unsigned_recordings[0].ends_with("s2.cast.age"),
            "got {:?}",
            r.unsigned_recordings
        );
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
