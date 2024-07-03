// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use crate::types::Bytes32;
use anyhow::{anyhow, Result};
use getset::Getters;

/// Length of hash digests in bytes.
pub const HASH_LEN: usize = 32;

/// A structure representing a hash value.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Getters, Hash)]
pub struct HashValue {
    #[getset(get = "pub(crate)")]
    hash: [u8; HASH_LEN],
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
    pub const fn new(hash: [u8; HASH_LEN]) -> Self {
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
    pub fn from_slice<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        <[u8; HASH_LEN]>::try_from(bytes.as_ref())
            .map_err(|e| anyhow!("Invalid length: {}", e))
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

impl From<Bytes32> for HashValue {
    fn from(bytes: Bytes32) -> Self {
        HashValue::new(bytes)
    }
}
