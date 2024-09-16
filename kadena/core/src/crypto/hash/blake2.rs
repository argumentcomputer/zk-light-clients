// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::HashValue;
use blake2::{Blake2s256, Digest};

/// Hash used to compute the PoW hash for a given block of the Kadena
/// chain.
pub type ChainwebPowHash = Blake2s256;

/// Hash the given data using the Blake2s256 hash function.
///
/// # Arguments
///
/// * `bytes` - The data to hash.
///
/// # Returns
///
/// The hash of the given data.
pub fn hash_data(bytes: &[u8]) -> Result<HashValue, CryptoError> {
    let mut hasher = Blake2s256::new();
    hasher.update(bytes);
    let output = hasher.finalize();

    HashValue::from_slice(output)
}
