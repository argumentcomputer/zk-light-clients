// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use crate::crypto::error::CryptoError;
use crate::types::Bytes32;
use anyhow::Result;
use getset::Getters;
use sha2::{Digest, Sha256};

/// Length of hash digests in bytes.
pub const HASH_LENGTH: usize = 32;

/// A structure representing a hash value.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Getters, Hash)]
pub struct HashValue {
    #[getset(get = "pub(crate)")]
    hash: [u8; HASH_LENGTH],
}

impl HashValue {
    /// Creates a new `HashValue` from a given hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - A byte array of length `HASH_LENGTH` representing the hash value.
    ///
    /// # Returns
    ///
    /// A new `HashValue` instance.
    pub const fn new(hash: [u8; HASH_LENGTH]) -> Self {
        HashValue { hash }
    }

    /// Creates a `HashValue` from a slice (e.g., retrieved from storage).
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice from which to create the `HashValue`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `HashValue` could be created successfully. If the slice has an invalid length,
    /// the `Result` is `Err` with an error message.
    pub fn from_slice<T: AsRef<[u8]>>(bytes: T) -> Result<Self, CryptoError> {
        <[u8; HASH_LENGTH]>::try_from(bytes.as_ref())
            .map_err(|_| CryptoError::DigestLength {
                expected: HASH_LENGTH,
                actual: bytes.as_ref().len(),
            })
            .map(Self::new)
    }

    /// Converts the `HashValue` into a vector.
    ///
    /// This method takes the hash value and converts it into a vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the hash value.
    pub fn to_vec(&self) -> Vec<u8> {
        self.hash.to_vec()
    }
}

impl AsRef<[u8; HASH_LENGTH]> for HashValue {
    fn as_ref(&self) -> &[u8; HASH_LENGTH] {
        &self.hash
    }
}

impl From<Bytes32> for HashValue {
    fn from(bytes: Bytes32) -> Self {
        HashValue::new(bytes)
    }
}

/// Hashes the input data using SHA-256.
///
/// # Arguments
///
/// * `input` - The input data to hash.
///
/// # Returns
///
/// A `HashValue` representing the SHA-256 hash of the input data.
pub fn sha2_hash(input: &[u8]) -> Result<HashValue, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    HashValue::from_slice(hasher.finalize())
}

// Function to hash two hash values
pub fn sha2_hash_concat(a: &HashValue, b: &HashValue) -> Result<HashValue, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(a.as_ref());
    hasher.update(b.as_ref());
    let result = hasher.finalize();
    let mut hash = [0; 32];
    hash.copy_from_slice(&result);
    HashValue::from_slice(hash)
}
