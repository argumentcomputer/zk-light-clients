// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Consensus block module
//!
//! This module contains the data structures used by the Beacon Node to store consensus-related
//! data.
//!
//! It mainly contains the `BeaconBlockHeader` data structure, which represent the header of a beacon block.

use crate::types::error::TypesError;
use crate::types::{Bytes32, BYTES_32_LEN, U64_LEN};
use getset::Getters;
use std::convert::TryInto;

/// Length in bytes of a serialized `BeaconBlockHeader`.
pub const BEACON_BLOCK_HEADER_BYTES_LEN: usize = BYTES_32_LEN * 3 + U64_LEN * 2;

/// `BeaconBlockHeader` represents the header of a beacon block.
///
/// From [the CL specifications](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblockheader).
#[derive(Debug, Default, Clone, Getters)]
#[getset(get = "pub")]
pub struct BeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: Bytes32,
    state_root: Bytes32,
    body_root: Bytes32,
}

impl BeaconBlockHeader {
    /// Serialize a `BeaconBlockHeader` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `BeaconBlockHeader` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Serialize slot
        bytes.extend(&self.slot.to_le_bytes());

        // Serialize proposer_index
        bytes.extend(&self.proposer_index.to_le_bytes());

        // Serialize parent_root
        bytes.extend(&self.parent_root);

        // Serialize state_root
        bytes.extend(&self.state_root);

        // Serialize body_root
        bytes.extend(&self.body_root);

        bytes
    }

    /// Deserialize a `BeaconBlockHeader` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `BeaconBlockHeader` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `BeaconBlockHeader` data structure or a `TypesError`.
    ///
    /// # Errors
    ///
    /// Returns a `TypesError` if the length of `bytes` is not equal to [`BEACON_BLOCK_HEADER_BYTES_LEN`] or
    /// if the conversion from bytes of internal types fails.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != BEACON_BLOCK_HEADER_BYTES_LEN {
            return Err(TypesError::InvalidLength {
                structure: "BeaconBlockHeader".into(),
                expected: BEACON_BLOCK_HEADER_BYTES_LEN,
                actual: bytes.len(),
            });
        }

        let cursor = 0;
        let slot = u64::from_le_bytes(bytes[cursor..cursor + U64_LEN].try_into().unwrap());

        let cursor = cursor + U64_LEN;
        let proposer_index =
            u64::from_le_bytes(bytes[cursor..cursor + U64_LEN].try_into().unwrap());

        let cursor = cursor + U64_LEN;
        let parent_root = bytes[cursor..cursor + BYTES_32_LEN].try_into().unwrap();

        let cursor = cursor + BYTES_32_LEN;
        let state_root = bytes[cursor..cursor + BYTES_32_LEN].try_into().unwrap();

        let cursor = cursor + BYTES_32_LEN;
        let body_root = bytes[cursor..cursor + BYTES_32_LEN].try_into().unwrap();

        Ok(Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env::current_dir;
    use std::fs;

    #[test]
    fn test_ssz_serde() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/BeaconBlockHeaderDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let beacon_block_header = BeaconBlockHeader::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = beacon_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
