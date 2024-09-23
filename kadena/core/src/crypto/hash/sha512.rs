// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::HashValue;
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
pub const fn tag_bytes(tag: u16) -> [u8; TAG_BYTES_LENGTH] {
    tag.to_be_bytes()
}

/// Hash the given data using the SHA-512 hash function following the
/// model of the Chainweb Merkle tree, along with a tag. To do so, it prepends the byte
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
pub fn hash_tagged_data(tag: u16, bytes: &[u8]) -> Result<HashValue, CryptoError> {
    let input = [&tag_bytes(tag), bytes].concat();
    hash_leaf(&input)
}

/// Hash the given data as a Merkle leaf using the SHA-512 hash function
/// following the model of the Chainweb Merkle tree. To do so, it prepends the byte
/// `0x0` to the data.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree).
///
/// # Arguments
///
/// * `bytes` - The data to hash.
///
/// # Returns
///
/// The hash of the given data.
pub fn hash_leaf(bytes: &[u8]) -> Result<HashValue, CryptoError> {
    let x: &[u8] = &[0x0];
    let input = [x, bytes].concat();
    hash_data(&input)
}

/// Hash the given data using the SHA-512 hash function.
///
/// # Arguments
///
/// * `bytes` - The data to hash.
///
///  # Returns
///
/// The hash of the given data.
pub fn hash_data(bytes: &[u8]) -> Result<HashValue, CryptoError> {
    let output = ChainwebHash::digest(bytes);

    HashValue::from_slice(output)
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
pub fn hash_inner(left: &[u8], right: &[u8]) -> Result<HashValue, CryptoError> {
    let x: &[u8] = &[0x1];
    let output = ChainwebHash::digest([x, left, right].concat().as_slice());

    HashValue::from_slice(output)
}
