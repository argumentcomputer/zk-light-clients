// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::hash::DIGEST_BYTES_LENGTH;
use crate::types::error::TypesError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha512Trunc256};

// Hash functions for Merkle tree nodes
// cf. https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#merke-log-trees
pub type ChainwebHash = Sha512Trunc256;

/// Size in bytes of a tag in the context of the Kadena chain.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const TAG_BYTES_LENGTH: usize = 2;

/// Convert a hash to a base64-encoded string.
///
/// # Arguments
///
/// * `hash` - The hash to convert.
///
/// # Returns
///
/// The base64-encoded hash.
pub fn hash_from_base64(base64: &[u8]) -> Result<[u8; DIGEST_BYTES_LENGTH], TypesError> {
    let decoded =
        URL_SAFE_NO_PAD
            .decode(base64)
            .map_err(|err| TypesError::DeserializationError {
                structure: "digest".to_string(),
                source: err.into(),
            })?;
    let mut arr = [0u8; DIGEST_BYTES_LENGTH];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

/// Convert a hash to a base64-encoded string.
///
/// # Arguments
///
/// * `hash` - The hash to convert.
///
/// # Returns
///
/// The base64-encoded hash.
pub const fn tag_bytes(tag: u16) -> [u8; TAG_BYTES_LENGTH] {
    tag.to_be_bytes()
}

/// Hash the given data using the SHA-512 hash function following the
/// model of the Chainweb Merkle tree. To do so, it prepends the byte
/// `0x0` to the data and a given tag.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree).
///
/// # Arguments
///
/// * `tag` - The tag to prepend to the data.
/// * `bytes` - The data to hash.
///
/// # Returns
///
/// The hash of the given data.
pub fn hash_data(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x0];
    ChainwebHash::digest([x, &tag_bytes(tag), bytes].concat().as_slice()).to_vec()
}

/// Hash the given data as some inner leaf using the SHA-512 hash function following the
/// model of the Chainweb Merkle tree. To do so, it prepends the byte
/// `0x1` to the data.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree).
///
/// # Arguments
///
/// * `left` - The left data to hash.
/// * `right` - The right data to hash.
///
/// # Returns
///
/// The hash of the given data.
pub fn hash_inner(left: &[u8], right: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x1];
    ChainwebHash::digest([x, left, right].concat().as_slice()).to_vec()
}
