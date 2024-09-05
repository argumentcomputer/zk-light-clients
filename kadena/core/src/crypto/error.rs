use thiserror::Error;

/// Errors possible while validating data.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid digest length: expected {expected}, got {actual}")]
    DigestLength { expected: usize, actual: usize },
}
