//! katagrapho top-level error type. Maps every failure to a sysexits.h
//! exit code so sysadmins can triage without grepping syslog.

use std::io;

// sysexits.h
pub const EX_USAGE: i32 = 64;
pub const EX_DATAERR: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_IOERR: i32 = 74;
pub const EX_NOPERM: i32 = 77;

#[derive(Debug, thiserror::Error)]
pub enum KatagraphoError {
    #[error("usage: {0}")]
    Usage(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("recipient file: {0}")]
    Recipient(String),

    #[error("privilege drop: {0}")]
    Privilege(String),

    #[error("storage: {0}")]
    Storage(String),

    #[error("encryption: {0}")]
    Encryption(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("internal: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

impl KatagraphoError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EX_USAGE,
            Self::Validation(_) => EX_DATAERR,
            Self::Recipient(_) => EX_NOINPUT,
            Self::Privilege(_) => EX_NOPERM,
            Self::Storage(_) => EX_IOERR,
            Self::Encryption(_) => EX_IOERR,
            Self::Io(_) => EX_IOERR,
            Self::Internal(_) => EX_SOFTWARE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct_per_class() {
        assert_eq!(KatagraphoError::Usage("x".into()).exit_code(), EX_USAGE);
        assert_eq!(KatagraphoError::Validation("x".into()).exit_code(), EX_DATAERR);
        assert_eq!(KatagraphoError::Recipient("x".into()).exit_code(), EX_NOINPUT);
        assert_eq!(KatagraphoError::Privilege("x".into()).exit_code(), EX_NOPERM);
        assert_eq!(KatagraphoError::Storage("x".into()).exit_code(), EX_IOERR);
        assert_eq!(KatagraphoError::Encryption("x".into()).exit_code(), EX_IOERR);
        assert_eq!(KatagraphoError::Internal("x".into()).exit_code(), EX_SOFTWARE);
    }
}
