// katagrapho — Setuid+setgid binary for tamper-proof session recording.
//
// Reads asciicinema data from stdin, optionally encrypts with age, and writes
// to /var/log/ssh-sessions/<user>/<session-id><suffix>.
//
// The binary runs setuid as a dedicated "session-writer" user and setgid as
// "ssh-sessions". Files are therefore owned by session-writer:ssh-sessions
// with mode 0440 — the recorded user cannot modify or delete them.

mod chain;
mod error;
mod finalize;
mod kata_config;
mod manifest;
mod signing;
mod stream;
mod verify;

use crate::error::KatagraphoError;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::process;

const STORAGE_DIR: &str = match option_env!("KATAGRAPHO_STORAGE_DIR") {
    Some(p) => p,
    None => "/var/log/ssh-sessions",
};
const BUF_SIZE: usize = 65536;
const MAX_SESSION_ID: usize = 128;
const MAX_USERNAME: usize = 64;
const MAX_SUFFIX: usize = 32;
const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024; // 512 MiB per session

const SAFE_ID_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
const SAFE_SUFFIX_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.";

// ---------------------------------------------------------------------------
// Security initialization
// ---------------------------------------------------------------------------

fn sanitize_environment() {
    for (key, _) in std::env::vars_os() {
        unsafe { std::env::remove_var(&key) };
    }
}

// ---------------------------------------------------------------------------
// Syslog audit logging
// ---------------------------------------------------------------------------

const SYSLOG_IDENT: &[u8] = b"katagrapho\0";

fn open_syslog() {
    unsafe {
        libc::openlog(
            SYSLOG_IDENT.as_ptr() as *const libc::c_char,
            libc::LOG_PID | libc::LOG_NDELAY,
            libc::LOG_AUTH,
        );
    }
}

fn close_syslog() {
    unsafe { libc::closelog() };
}

fn syslog_msg(priority: libc::c_int, msg: &str) {
    let fmt = CString::new("%s").unwrap();
    let c_msg = match CString::new(msg) {
        Ok(s) => s,
        Err(_) => return,
    };
    unsafe { libc::syslog(priority, fmt.as_ptr(), c_msg.as_ptr()) };
}

/// Set a restrictive umask before any filesystem operations.
fn set_umask() {
    unsafe {
        libc::umask(0o027);
    }
}

/// Close all inherited file descriptors >= 3.
fn close_inherited_fds() {
    // close_range(3, UINT_MAX, 0) — single syscall, Linux 5.9+.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if ret == 0 {
        return;
    }
    // Fallback: enumerate /proc/self/fd.
    if let Ok(dir) = fs::read_dir("/proc/self/fd") {
        let fds: Vec<i32> = dir
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .filter(|&fd| fd >= 3)
            .collect();
        for fd in fds {
            unsafe { libc::close(fd) };
        }
    }
}

/// Reset resource limits to prevent caller manipulation.
fn reset_resource_limits() -> Result<(), KatagraphoError> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
        return Err(KatagraphoError::Privilege(format!(
            "cannot reset RLIMIT_CORE: {}",
            io::Error::last_os_error()
        )));
    }

    let fsize = libc::rlimit {
        rlim_cur: MAX_FILE_SIZE + 1024 * 1024,
        rlim_max: MAX_FILE_SIZE + 1024 * 1024,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &fsize) } != 0 {
        return Err(KatagraphoError::Privilege(format!(
            "cannot reset RLIMIT_FSIZE: {}",
            io::Error::last_os_error()
        )));
    }

    let nofile = libc::rlimit {
        rlim_cur: 64,
        rlim_max: 64,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &nofile) } != 0 {
        return Err(KatagraphoError::Privilege(format!(
            "cannot reset RLIMIT_NOFILE: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Harden process against debugging and privilege escalation.
fn harden_process() -> Result<(), KatagraphoError> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) } != 0 {
        return Err(KatagraphoError::Privilege(format!(
            "PR_SET_DUMPABLE: {}",
            io::Error::last_os_error()
        )));
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0_u64, 0_u64, 0_u64) } != 0 {
        return Err(KatagraphoError::Privilege(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// User identity
// ---------------------------------------------------------------------------

/// Resolve the real username of the calling process via getuid()/getpwuid().
/// This is immune to caller spoofing — unlike a --user flag, the kernel
/// provides the real UID.
fn resolve_caller_username() -> Result<String, KatagraphoError> {
    // SAFETY: getuid() is always safe and cannot fail.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getpwuid returns a pointer to a static buffer (or null).
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(KatagraphoError::Privilege(format!(
            "cannot resolve username for uid {uid}"
        )));
    }
    // SAFETY: pw_name is a valid C string when pw is non-null.
    let name = unsafe { CStr::from_ptr((*pw).pw_name) };
    name.to_str()
        .map(|s| s.to_string())
        .map_err(|_| KatagraphoError::Privilege("username is not valid UTF-8".to_string()))
}

/// Lock privilege transition: make euid/egid permanent and irrevocable.
/// Must be called AFTER resolve_caller_username() since getuid() changes.
fn lock_privileges() -> Result<(), KatagraphoError> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    if unsafe { libc::setresgid(egid, egid, egid) } != 0 {
        return Err(KatagraphoError::Privilege(format!(
            "setresgid: {}",
            io::Error::last_os_error()
        )));
    }
    if unsafe { libc::setresuid(euid, euid, euid) } != 0 {
        return Err(KatagraphoError::Privilege(format!(
            "setresuid: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate(
    input: &str,
    max_len: usize,
    allowed: &str,
    label: &str,
) -> Result<(), KatagraphoError> {
    if input.is_empty() {
        return Err(KatagraphoError::Validation(format!(
            "{label} cannot be empty"
        )));
    }
    if input.len() > max_len {
        return Err(KatagraphoError::Validation(format!(
            "{label} too long (max {max_len})"
        )));
    }
    if let Some(ch) = input.chars().find(|c| !allowed.contains(*c)) {
        return Err(KatagraphoError::Validation(format!(
            "{label} contains invalid character: '{ch}'"
        )));
    }
    Ok(())
}

/// Validate that a path resolves to a real directory inside STORAGE_DIR.
fn validate_directory(path: &Path) -> Result<(), KatagraphoError> {
    let resolved = fs::canonicalize(path).map_err(|e| {
        KatagraphoError::Storage(format!("cannot resolve '{}': {e}", path.display()))
    })?;

    // Path::starts_with checks component boundaries, so
    // "/var/log/ssh-sessions-evil" will NOT match "/var/log/ssh-sessions".
    if !resolved.starts_with(STORAGE_DIR) {
        return Err(KatagraphoError::Storage(
            "path resolves outside storage directory".to_string(),
        ));
    }

    // canonicalize() already resolved all symlinks, so the resolved path
    // itself cannot be a symlink. We only need to confirm it is a directory.
    let meta = fs::symlink_metadata(&resolved)
        .map_err(|e| KatagraphoError::Storage(format!("cannot stat: {e}")))?;
    if !meta.is_dir() {
        return Err(KatagraphoError::Storage(format!(
            "'{}' is not a directory",
            path.display()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Load age recipients (public keys) from a file.
/// Each line is either an age public key or a comment (starting with #).
fn load_recipients(path: &str) -> Result<Vec<Box<dyn age::Recipient + Send>>, KatagraphoError> {
    let contents = fs::read_to_string(path).map_err(|e| {
        KatagraphoError::Recipient(format!("cannot read recipient file '{path}': {e}"))
    })?;

    let recipients: Vec<Box<dyn age::Recipient + Send>> = contents
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|l| {
            l.parse::<age::x25519::Recipient>()
                .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
                .map_err(|_| {
                    KatagraphoError::Recipient("invalid age recipient in file".to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if recipients.is_empty() {
        return Err(KatagraphoError::Recipient(format!(
            "no recipients found in '{path}'"
        )));
    }
    Ok(recipients)
}

/// Stream stdin to the given writer with a size limit.
/// Returns the total number of bytes read from stdin.
fn stream_stdin(writer: &mut dyn Write) -> Result<u64, KatagraphoError> {
    let mut buf = [0u8; BUF_SIZE];
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut total_read: u64 = 0;

    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(KatagraphoError::Io(e));
            }
        };

        total_read += n as u64;
        if total_read > MAX_FILE_SIZE {
            return Err(KatagraphoError::Storage(format!(
                "session exceeds maximum size ({MAX_FILE_SIZE} bytes)"
            )));
        }

        if let Err(e) = writer.write_all(&buf[..n]) {
            return Err(KatagraphoError::Io(e));
        }
    }

    Ok(total_read)
}

/// Attempt to write a termination marker to the recording.
/// This is best-effort — if writing fails, we still want to preserve
/// whatever partial data we have.
fn write_termination_marker(writer: &mut dyn Write, reason: &str) {
    // Use a fixed large elapsed time to ensure it sorts last.
    let marker = format!("[999999.0, \"x\", {:?}]\n", reason);
    let _ = writer.write_all(marker.as_bytes());
}

// ---------------------------------------------------------------------------
// Directory management
// ---------------------------------------------------------------------------

fn ensure_user_dir(username: &str) -> Result<PathBuf, KatagraphoError> {
    let dir = PathBuf::from(format!("{STORAGE_DIR}/{username}"));

    // Use DirBuilder to pass the mode directly to mkdir(2).
    // The parent dirs setgid bit auto-inherits to subdirectories
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o0750);

    match builder.create(&dir) {
        Ok(()) => Ok(dir),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            validate_directory(&dir)?;
            Ok(dir)
        }
        Err(e) => Err(KatagraphoError::Storage(format!(
            "mkdir '{}': {e}",
            dir.display()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Args {
    session_id: String,
    suffix: String,
    recipient_file: Option<String>,
    no_encrypt: bool,
}

fn parse_args() -> Result<Args, KatagraphoError> {
    let args: Vec<String> = std::env::args().collect();
    let mut session_id = None;
    let mut suffix: Option<String> = None;
    let mut recipient_file: Option<String> = None;
    let mut no_encrypt = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!(
                    "katagrapho {} ({})",
                    env!("CARGO_PKG_VERSION"),
                    env!("KATAGRAPHO_GIT_COMMIT")
                );
                process::exit(0);
            }
            "--session-id" if i + 1 < args.len() => {
                i += 1;
                session_id = Some(args[i].clone());
            }
            "--suffix" if i + 1 < args.len() => {
                i += 1;
                suffix = Some(args[i].clone());
            }
            "--recipient-file" if i + 1 < args.len() => {
                i += 1;
                recipient_file = Some(args[i].clone());
            }
            "--no-encrypt" => {
                no_encrypt = true;
            }
            // Known flags without a following value.
            "--session-id" | "--suffix" | "--recipient-file" => {
                return Err(KatagraphoError::Usage(format!(
                    "{} requires a value",
                    args[i]
                )));
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: katagrapho --session-id <ID> (--recipient-file <FILE> | --no-encrypt) [--suffix <SUFFIX>]"
                );
                eprintln!("Username is resolved automatically from the calling process UID.");
                eprintln!();
                eprintln!("  --session-id <ID>         Session identifier (required)");
                eprintln!(
                    "  --recipient-file <FILE>   Path to age recipients file (required unless --no-encrypt)"
                );
                eprintln!(
                    "  --no-encrypt              Disable encryption; write plaintext .cast file"
                );
                eprintln!(
                    "  --suffix <SUFFIX>         Override output file suffix (default: .cast.age or .cast with --no-encrypt)"
                );
                eprintln!("  --version, -V             Print version and git commit");
                process::exit(0);
            }
            other => {
                return Err(KatagraphoError::Usage(format!("unknown argument: {other}")));
            }
        }
        i += 1;
    }

    let default_suffix = if no_encrypt {
        String::from(".cast")
    } else {
        String::from(".cast.age")
    };

    Ok(Args {
        session_id: session_id
            .ok_or_else(|| KatagraphoError::Usage("--session-id required".to_string()))?,
        suffix: suffix.unwrap_or(default_suffix),
        recipient_file,
        no_encrypt,
    })
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaddset(&mut sa.sa_mask, libc::SIGTERM);
        libc::sigaddset(&mut sa.sa_mask, libc::SIGINT);
        sa.sa_sigaction = handle_signal as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        if libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) != 0 {
            process::abort();
        }
        if libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut()) != 0 {
            process::abort();
        }
    }
}

fn run() -> Result<(), KatagraphoError> {
    sanitize_environment();
    set_umask();
    close_inherited_fds();
    reset_resource_limits()?;
    harden_process()?;
    open_syslog();
    install_signal_handlers();

    let args = parse_args()?;

    if !args.no_encrypt && args.recipient_file.is_none() {
        return Err(KatagraphoError::Usage(
            "--recipient-file is required (use --no-encrypt to explicitly disable encryption)"
                .to_string(),
        ));
    }
    if args.no_encrypt && args.recipient_file.is_some() {
        return Err(KatagraphoError::Usage(
            "--no-encrypt and --recipient-file are mutually exclusive".to_string(),
        ));
    }

    if let Some(ref rf) = args.recipient_file {
        let rf_path = Path::new(rf);
        let resolved = fs::canonicalize(rf_path).map_err(|e| {
            KatagraphoError::Recipient(format!("cannot resolve recipient file '{rf}': {e}"))
        })?;
        let allowed_dirs = ["/etc/katagrapho", "/etc/age", "/etc/epitropos"];
        let in_allowed_dir = allowed_dirs.iter().any(|d| resolved.starts_with(d));
        if !in_allowed_dir {
            return Err(KatagraphoError::Recipient(format!(
                "recipient file must be in /etc/katagrapho/, /etc/age/, or /etc/epitropos/ (got '{}')",
                resolved.display()
            )));
        }
    }

    let username = resolve_caller_username()?;
    lock_privileges()?;

    syslog_msg(
        libc::LOG_INFO,
        &format!(
            "session start: user={username} session_id={}",
            args.session_id
        ),
    );

    validate(
        &args.session_id,
        MAX_SESSION_ID,
        SAFE_ID_CHARS,
        "session-id",
    )?;
    validate(&username, MAX_USERNAME, SAFE_ID_CHARS, "username")?;

    if !args.suffix.starts_with('.') {
        return Err(KatagraphoError::Validation(
            "suffix must start with '.'".to_string(),
        ));
    }
    if args.suffix.starts_with("..") {
        return Err(KatagraphoError::Validation(
            "suffix cannot start with '..'".to_string(),
        ));
    }
    validate(
        &args.suffix[1..],
        MAX_SUFFIX - 1,
        SAFE_SUFFIX_CHARS,
        "suffix",
    )?;

    let user_dir = ensure_user_dir(&username)?;
    let filename = format!("{}{}", args.session_id, args.suffix);
    let output_path = user_dir.join(&filename);

    // Verify the assembled path stays within STORAGE_DIR.
    // Path::starts_with checks component boundaries correctly.
    if !output_path.starts_with(STORAGE_DIR) {
        return Err(KatagraphoError::Storage(
            "path escapes storage directory".to_string(),
        ));
    }

    // Open the user directory with O_DIRECTORY | O_NOFOLLOW to get a
    // race-free file descriptor. This prevents TOCTOU attacks where the
    // directory is replaced with a symlink between validation and file open.
    let dir_cstr =
        CString::new(user_dir.to_str().ok_or_else(|| {
            KatagraphoError::Storage("user directory path not UTF-8".to_string())
        })?)
        .map_err(|_| KatagraphoError::Storage("directory path contains null byte".to_string()))?;

    let dir_fd = unsafe {
        libc::open(
            dir_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dir_fd < 0 {
        return Err(KatagraphoError::Storage(format!(
            "open directory '{}': {}",
            user_dir.display(),
            io::Error::last_os_error()
        )));
    }

    // Use openat() relative to the directory fd to create the file.
    // O_CREAT|O_EXCL: atomic create, fail if exists.
    // O_NOFOLLOW: refuse to follow symlinks in the filename.
    // Mode 0440: read-only for owner (session-writer) + group (ssh-sessions).
    let filename_cstr = CString::new(filename.as_str())
        .map_err(|_| KatagraphoError::Storage("filename contains null byte".to_string()))?;

    let file_fd = unsafe {
        libc::openat(
            dir_fd,
            filename_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o0440 as libc::c_uint,
        )
    };

    // Close the directory fd regardless of openat result.
    unsafe {
        libc::close(dir_fd);
    }

    if file_fd < 0 {
        return Err(KatagraphoError::Storage(format!(
            "open '{}': {}",
            output_path.display(),
            io::Error::last_os_error()
        )));
    }

    // SAFETY: file_fd is a valid, exclusively-owned file descriptor.
    let mut file = unsafe { fs::File::from_raw_fd(file_fd) };

    // Load signing key + chain paths from config (defaults apply if no --config).
    let kata_cfg = crate::kata_config::KataConfig::default();
    let signing_key = crate::signing::KeyPair::load(&kata_cfg.signing.key_path, &kata_cfg.signing.pub_path);
    let chain_paths = crate::chain::ChainPaths::under(&kata_cfg.chain.dir);

    // Process the kgv1 stream: forward raw bytes into the encrypted file,
    // collect chunks and the header for the manifest.
    let v1_result = process_v1_stream(&mut file, &args.recipient_file);

    file.sync_all().map_err(KatagraphoError::Io)?;

    let (header_info, chunks, end_reason, exit_code) = match v1_result {
        Ok(t) => t,
        Err(e) => {
            syslog_msg(
                libc::LOG_ERR,
                &format!(
                    "session error: user={username} session_id={}: {e}",
                    args.session_id
                ),
            );
            close_syslog();
            return Err(e);
        }
    };

    // If signing key loaded, write manifest + advance chain. If not (e.g.
    // test env or missing key), log a warning but succeed — recording is
    // complete, just not attested.
    if let Ok(key) = signing_key {
        if let Err(e) = write_manifest_and_advance(
            &key,
            &chain_paths,
            &output_path,
            &username,
            &args.session_id,
            &header_info,
            &chunks,
            &end_reason,
            exit_code,
        ) {
            syslog_msg(
                libc::LOG_ERR,
                &format!(
                    "manifest write failed: user={username} session_id={}: {e}",
                    args.session_id
                ),
            );
            // Continue: the recording itself is on disk, just unsigned.
        }
    } else {
        syslog_msg(
            libc::LOG_WARNING,
            &format!(
                "no signing key at {}; recording written without manifest",
                kata_cfg.signing.key_path.display()
            ),
        );
    }

    syslog_msg(
        libc::LOG_INFO,
        &format!(
            "session end: user={username} session_id={} file={} chunks={}",
            args.session_id,
            output_path.display(),
            chunks.len(),
        ),
    );
    close_syslog();
    Ok(())
}

/// Parse the kgv1 stream from stdin, forward every record into the
/// encrypted (or plaintext) output file, and collect the header + chunks.
fn process_v1_stream(
    file: &mut fs::File,
    recipient_file: &Option<String>,
) -> Result<
    (
        crate::stream::HeaderInfo,
        Vec<crate::manifest::Chunk>,
        String,
        i32,
    ),
    KatagraphoError,
> {
    use crate::finalize::EncryptionFinalizer;
    use crate::stream::{Event, Reader as StreamReader};

    let stdin = io::stdin();
    let locked = stdin.lock();
    let mut reader = StreamReader::new(locked);

    let mut header_info: Option<crate::stream::HeaderInfo> = None;
    let mut chunks: Vec<crate::manifest::Chunk> = Vec::new();
    let mut end_reason = "eof".to_string();
    let mut exit_code = 0;

    // Encrypted path
    if let Some(recipient_path) = recipient_file {
        let recipients = load_recipients(recipient_path)?;
        let recipients_ref: Vec<&dyn age::Recipient> = recipients
            .iter()
            .map(|r| r.as_ref() as &dyn age::Recipient)
            .collect();
        let encryptor = age::Encryptor::with_recipients(recipients_ref.into_iter())
            .map_err(|e| KatagraphoError::Encryption(format!("setup: {e}")))?;
        let inner = encryptor
            .wrap_output(file)
            .map_err(|e| KatagraphoError::Encryption(format!("init: {e}")))?;
        let mut fin = EncryptionFinalizer::new(inner);

        while let Some((event, raw)) = reader.next_event()? {
            if SHUTDOWN.load(Ordering::SeqCst) {
                end_reason = "signal".to_string();
                break;
            }
            fin.write_all(&raw).map_err(KatagraphoError::Io)?;
            match event {
                Event::Header(h) => {
                    if header_info.is_some() {
                        return Err(KatagraphoError::Stream(
                            "second header record".to_string(),
                        ));
                    }
                    header_info = Some(h);
                }
                Event::Chunk(c) => {
                    chunks.push(crate::manifest::Chunk {
                        seq: c.seq,
                        bytes: c.bytes,
                        messages: c.messages,
                        elapsed: c.elapsed,
                        sha256: c.sha256_hex,
                    });
                }
                Event::End { reason, exit_code: ec, .. } => {
                    end_reason = reason;
                    exit_code = ec;
                    break;
                }
                _ => {}
            }
        }

        fin.finish()
            .map_err(|e| KatagraphoError::Encryption(format!("finalize: {e}")))?;
    } else {
        // Plaintext path
        while let Some((event, raw)) = reader.next_event()? {
            if SHUTDOWN.load(Ordering::SeqCst) {
                end_reason = "signal".to_string();
                break;
            }
            file.write_all(&raw).map_err(KatagraphoError::Io)?;
            match event {
                Event::Header(h) => {
                    if header_info.is_some() {
                        return Err(KatagraphoError::Stream(
                            "second header record".to_string(),
                        ));
                    }
                    header_info = Some(h);
                }
                Event::Chunk(c) => {
                    chunks.push(crate::manifest::Chunk {
                        seq: c.seq,
                        bytes: c.bytes,
                        messages: c.messages,
                        elapsed: c.elapsed,
                        sha256: c.sha256_hex,
                    });
                }
                Event::End { reason, exit_code: ec, .. } => {
                    end_reason = reason;
                    exit_code = ec;
                    break;
                }
                _ => {}
            }
        }
    }

    let header =
        header_info.ok_or_else(|| KatagraphoError::Stream("stream had no header".to_string()))?;
    Ok((header, chunks, end_reason, exit_code))
}

#[allow(clippy::too_many_arguments)]
fn write_manifest_and_advance(
    key: &crate::signing::KeyPair,
    chain_paths: &crate::chain::ChainPaths,
    recording_path: &Path,
    username: &str,
    session_id: &str,
    header: &crate::stream::HeaderInfo,
    chunks: &[crate::manifest::Chunk],
    end_reason: &str,
    exit_code: i32,
) -> Result<(), KatagraphoError> {
    let recording_sha256 = sha256_file(recording_path)?;
    let recording_size = fs::metadata(recording_path)
        .map_err(|e| KatagraphoError::Manifest(format!("stat recording: {e}")))?
        .len();

    let _lock = crate::chain::ChainLock::acquire(chain_paths)?;
    let prev = crate::chain::read_head(chain_paths)?;

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let mut manifest = crate::manifest::Manifest {
        v: crate::manifest::MANIFEST_VERSION.to_string(),
        session_id: session_id.to_string(),
        part: 0,
        user: username.to_string(),
        host: header.host.clone(),
        boot_id: header.boot_id.clone(),
        audit_session_id: header.audit_session_id,
        started: header.started,
        ended: now_unix,
        katagrapho_version: env!("CARGO_PKG_VERSION").to_string(),
        katagrapho_commit: env!("KATAGRAPHO_GIT_COMMIT").to_string(),
        epitropos_version: header.epitropos_version.clone(),
        epitropos_commit: header.epitropos_commit.clone(),
        recording_file: recording_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        recording_size,
        recording_sha256,
        chunks: chunks.to_vec(),
        end_reason: end_reason.to_string(),
        exit_code,
        prev_manifest_hash: prev,
        this_manifest_hash: String::new(),
        key_id: String::new(),
        signature: String::new(),
    };
    manifest.sign(key)?;

    let sidecar = sidecar_path_for(recording_path);
    manifest.write_to(&sidecar)?;

    crate::chain::write_head(chain_paths, &manifest.this_manifest_hash)?;

    let iso_now = iso_timestamp_utc();
    crate::chain::append_log(
        chain_paths,
        &iso_now,
        username,
        session_id,
        0,
        &manifest.this_manifest_hash,
    )?;

    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, KatagraphoError> {
    use sha2::{Digest, Sha256};
    let mut f = fs::File::open(path)
        .map_err(|e| KatagraphoError::Manifest(format!("open recording: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = Read::read(&mut f, &mut buf)
            .map_err(|e| KatagraphoError::Manifest(format!("read recording: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sidecar_path_for(recording: &Path) -> PathBuf {
    let mut s = recording.as_os_str().to_os_string();
    s.push(".manifest.json");
    PathBuf::from(s)
}

fn iso_timestamp_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let hms = secs % 86400;
    let h = hms / 3600;
    let m = (hms % 3600) / 60;
    let s = hms % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's days-from-civil conversion. Input: days since 1970-01-01.
fn days_to_ymd(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("katagrapho: {e}");
            close_syslog();
            process::exit(e.exit_code());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty() {
        assert!(validate("", 128, SAFE_ID_CHARS, "test").is_err());
    }

    #[test]
    fn validate_rejects_too_long() {
        let long = "a".repeat(129);
        assert!(validate(&long, 128, SAFE_ID_CHARS, "test").is_err());
    }

    #[test]
    fn validate_rejects_bad_chars() {
        assert!(validate("hello/world", 128, SAFE_ID_CHARS, "test").is_err());
        assert!(validate("hello world", 128, SAFE_ID_CHARS, "test").is_err());
        assert!(validate("../evil", 128, SAFE_ID_CHARS, "test").is_err());
    }

    #[test]
    fn validate_accepts_good_ids() {
        assert!(validate("abc123", 128, SAFE_ID_CHARS, "test").is_ok());
        assert!(validate("session_id-001.test", 128, SAFE_ID_CHARS, "test").is_ok());
    }

    #[test]
    fn validate_suffix_chars() {
        assert!(validate("cast.age", 32, SAFE_SUFFIX_CHARS, "suffix").is_ok());
        assert!(validate("cast/evil", 32, SAFE_SUFFIX_CHARS, "suffix").is_err());
    }

    #[test]
    fn validate_directory_rejects_outside_storage() {
        let result = validate_directory(Path::new("/tmp"));
        assert!(result.is_err());
    }

    #[test]
    fn validate_directory_rejects_nonexistent() {
        let result = validate_directory(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn termination_marker_format() {
        let mut buf = Vec::new();
        write_termination_marker(&mut buf, "test error");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("[999999.0"));
        assert!(s.contains("test error"));
        assert!(s.contains("\"x\""));
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn validate_directory_rejects_symlink_outside_storage() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("evil");
        symlink("/tmp", &link).unwrap();
        let result = validate_directory(&link);
        assert!(result.is_err(), "symlink to /tmp should be rejected");
    }

    #[test]
    fn sanitize_environment_removes_all_vars() {
        unsafe {
            std::env::set_var("LD_PRELOAD", "/evil.so");
            std::env::set_var("PATH", "/usr/bin");
        }
        sanitize_environment();
        assert!(std::env::var("LD_PRELOAD").is_err());
        assert!(std::env::var("PATH").is_err());
    }
}
