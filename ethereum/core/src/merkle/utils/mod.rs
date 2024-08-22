// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::{sha2_hash, sha2_hash_concat, HashValue};
use crate::types::BYTES_32_LEN;

pub mod rlp;

/// Returns the index of the subtree that a given generalized index belongs to. The generalized index
/// is the index of a leaf in a binary tree where the leaves are numbered from left to right.
///
/// # Arguments
///
/// * `generalized_index` - The generalized index of the leaf.
///
/// # Returns
///
/// The index of the subtree that the leaf belongs to.
///
/// # Notes
///
/// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#get_subtree_index).
pub const fn get_subtree_index(generalized_index: u64) -> u64 {
    // Calculate floor(log2(generalized_index)) using bit manipulation
    let floor_log2 = 63 - generalized_index.leading_zeros();

    // Calculate 2^floor(log2(generalized_index))
    let power_of_two = 1u64 << floor_log2;

    // Return the remainder of generalized_index divided by 2^floor(log2(generalized_index))
    generalized_index % power_of_two
}

/// The type of data that can be used to compute a Merkle root.
pub enum DataType {
    Bytes(Vec<u8>),
    Struct(Vec<HashValue>),
    List(Vec<HashValue>),
}

/// Computes the Merkle root of the given data.
///
/// # Arguments
///
/// * `data_type` - The type of data to compute the Merkle root of.
///
/// # Returns
///
/// The Merkle root of the given data.
pub fn merkle_root(data_type: DataType) -> Result<HashValue, CryptoError> {
    match data_type {
        DataType::Bytes(bytes) => {
            if bytes.is_empty() {
                Ok(HashValue::default())
            } else if bytes.len() < BYTES_32_LEN {
                let mut leaves = [0; BYTES_32_LEN];
                leaves[0..bytes.len()].copy_from_slice(&bytes);
                Ok(HashValue::new(leaves))
            } else if bytes.len() > BYTES_32_LEN && bytes.len() <= BYTES_32_LEN * 2 {
                let mut leaves = [0; BYTES_32_LEN * 2];
                leaves[0..bytes.len()].copy_from_slice(&bytes);
                sha2_hash(&leaves)
            } else {
                let data_roots = bytes
                    .chunks(32)
                    .map(HashValue::from_slice)
                    .collect::<Result<Vec<HashValue>, _>>()?;

                calculate_root(data_roots)
            }
        }
        DataType::Struct(elts) | DataType::List(elts) => calculate_root(elts),
    }
}

/// Computes the root of a Merkle tree given a list of leaves.
///
/// # Arguments
///
/// * `leaves` - The leaves of the Merkle tree.
///
/// # Returns
///
/// The root of the Merkle tree.
fn calculate_root(mut leaves: Vec<HashValue>) -> Result<HashValue, CryptoError> {
    // Parameters for the `ExecutionBlockHeader` Merkle tree
    let num_leaves = leaves.len().next_power_of_two();
    let empty_leaf = HashValue::default();

    // Pad the leaves vector with empty_leaf to ensure the tree is balanced
    while leaves.len() < num_leaves {
        leaves.push(empty_leaf);
    }

    // Compute the root of the Merkle tree
    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        for i in (0..leaves.len()).step_by(2) {
            let combined_hash = sha2_hash_concat(&leaves[i], &leaves[i + 1])?;
            next_level.push(combined_hash);
        }
        leaves = next_level;
    }

    Ok(leaves[0])
}

/// Mixes a base hash with its original data size value. Used in SSZ Merkleization for list with a
/// variable number of elements.
///
/// # Arguments
///
/// * `base_hash` - The base hash to mix.
/// * `size` - The size of the original data.
///
/// # Returns
///
/// The mixed hash.
pub fn mix_size(base_hash: &HashValue, size: usize) -> Result<HashValue, CryptoError> {
    let usize_len = size_of::<usize>();

    let mut length_bytes = [0; BYTES_32_LEN];
    length_bytes[0..usize_len].copy_from_slice(&size.to_le_bytes());

    sha2_hash_concat(base_hash, &HashValue::new(length_bytes))
}

/// Returns the index of the subtree that a given generalized index belongs to. The generalized index
/// is the index of a leaf in a binary tree where the leaves are numbered from left to right.
pub const fn get_nibble(path: &[u8], offset: usize) -> u8 {
    let byte = path[offset / 2];
    if offset % 2 == 0 {
        byte >> 4
    } else {
        byte & 0xF
    }
}
