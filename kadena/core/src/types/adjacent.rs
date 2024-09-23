// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::hash::DIGEST_BYTES_LENGTH;
use crate::types::graph::TWENTY_CHAIN_GRAPH_DEGREE;
use crate::types::header::chain::CHAIN_BYTES_LENGTH;
use crate::types::U16_BYTES_LENGTH;

/// Size in bytes of the value for the adjacent parent. Contains the
/// length of the adjacent parent record and the adjacent parent
/// record itself.
pub const ADJACENTS_RAW_BYTES_LENGTH: usize = U16_BYTES_LENGTH + ADJACENT_RECORD_RAW_BYTES_LENGTH;

/// Size in bytes of the adjacent parent record (without length prefix).
pub const ADJACENT_RECORD_RAW_BYTES_LENGTH: usize =
    TWENTY_CHAIN_GRAPH_DEGREE * ADJACENT_PARENT_RAW_BYTES_LENGTH;

/// Size in bytes of an entry in the the adjacent parent record.
pub const ADJACENT_PARENT_RAW_BYTES_LENGTH: usize = CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH;

/// Number of adjacent parents per block.
pub const ADJACENT_RECORD_PER_BLOCK: usize = TWENTY_CHAIN_GRAPH_DEGREE;

/// Represent an adjacent parent in raw form for a Kadena block.
pub struct AdjacentParentRaw {
    chain: [u8; CHAIN_BYTES_LENGTH],
    hash: [u8; DIGEST_BYTES_LENGTH],
}

impl AdjacentParentRaw {
    /// Create an `AdjacentParentRaw` from a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The slice of bytes to convert to an `AdjacentParentRaw`.
    ///
    /// # Returns
    ///
    /// The `AdjacentParentRaw` created from the slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let chain: [u8; CHAIN_BYTES_LENGTH] = bytes[0..CHAIN_BYTES_LENGTH].try_into().unwrap();
        let hash: [u8; DIGEST_BYTES_LENGTH] = bytes
            [CHAIN_BYTES_LENGTH..CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH]
            .try_into()
            .unwrap();

        Self { chain, hash }
    }
}

/// Represent an adjacent parent in a Kadena block in Rust types.
#[derive(Debug)]
pub struct AdjacentParent {
    chain: u32,
    hash: [u8; DIGEST_BYTES_LENGTH],
}

impl From<&AdjacentParentRaw> for AdjacentParent {
    fn from(raw: &AdjacentParentRaw) -> Self {
        let chain = u32::from_le_bytes(raw.chain);
        let hash = raw.hash;

        Self { chain, hash }
    }
}

/// Represents a record of all the adjacent parents of a Kadena block
/// with its properties serialized as bytes.
pub struct AdjacentParentRecordRaw {
    length: [u8; U16_BYTES_LENGTH],
    adjacents: [u8; ADJACENT_RECORD_RAW_BYTES_LENGTH],
}

impl AdjacentParentRecordRaw {
    /// Create an `AdjacentParentRecordRaw` from a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The slice of bytes to convert to an `AdjacentParentRecordRaw`.
    ///
    /// # Returns
    ///
    /// The `AdjacentParentRecordRaw` created from the slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let length: [u8; U16_BYTES_LENGTH] = bytes[0..U16_BYTES_LENGTH].try_into().unwrap();
        let adjacents: [u8; ADJACENT_RECORD_RAW_BYTES_LENGTH] = bytes
            [U16_BYTES_LENGTH..ADJACENTS_RAW_BYTES_LENGTH]
            .try_into()
            .unwrap();

        Self { length, adjacents }
    }
}

impl From<AdjacentParent> for AdjacentParentRaw {
    fn from(adjacent: AdjacentParent) -> Self {
        let chain = adjacent.chain.to_le_bytes();
        let hash = adjacent.hash;

        Self { chain, hash }
    }
}

/// Represents a record of all the adjacent parents of a Kadena block
/// with its properties as Rust types.
#[repr(align(1))]
#[derive(Debug)]
#[allow(dead_code)]
pub struct AdjacentParentRecord {
    length: u16,
    adjacents: Vec<AdjacentParent>,
}

impl From<AdjacentParentRecordRaw> for AdjacentParentRecord {
    fn from(raw: AdjacentParentRecordRaw) -> Self {
        let length = u16::from_le_bytes(raw.length);

        let mut adjacents = vec![];
        for i in 0..length as usize {
            let start = i * CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH;
            let end = start + CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH;
            adjacents.push(AdjacentParent::from(&AdjacentParentRaw::from_bytes(
                raw.adjacents[start..end]
                    .try_into()
                    .expect("Should be able to convert raw adjacent parent to fixed slice"),
            )));
        }

        // just in case
        adjacents.sort_unstable_by_key(|v| v.chain);

        Self { length, adjacents }
    }
}

impl AdjacentParentRecord {
    /// Get the hashes of the adjacent parents.
    ///
    /// # Returns
    ///
    /// The hashes of the adjacent parents.
    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.adjacents.iter().map(|a| a.hash).collect()
    }
}
