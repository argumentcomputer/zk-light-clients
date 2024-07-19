// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Consensus block module
//!
//! This module contains the data structures used by the Beacon Node to store consensus-related
//! data.
//!
//! It mainly contains the `BeaconBlockHeader` data structure, which represent the header of a beacon block.

use crate::crypto::error::CryptoError;
use crate::crypto::hash::HashValue;
use crate::merkle::utils::{merkle_root, DataType};
use crate::merkle::Merkleized;
use crate::types::error::TypesError;
use crate::types::utils::{extract_fixed_bytes, extract_u64, u64_to_bytes32, U64_LEN};
use crate::types::{Bytes32, BYTES_32_LEN};
use getset::Getters;

/// Length in bytes of a serialized `BeaconBlockHeader`.
pub const BEACON_BLOCK_HEADER_BYTES_LEN: usize = BYTES_32_LEN * 3 + U64_LEN * 2;

/// `BeaconBlockHeader` represents the header of a beacon block.
///
/// From [the CL specifications](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblockheader).
#[derive(Debug, Default, Clone, Eq, PartialEq, Getters)]
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
        let (cursor, slot) = extract_u64("BeaconBlockHeader", bytes, cursor)?;
        let (cursor, proposer_index) = extract_u64("BeaconBlockHeader", bytes, cursor)?;
        let (cursor, parent_root) =
            extract_fixed_bytes::<BYTES_32_LEN>("BeaconBlockHeader", bytes, cursor)?;
        let (cursor, state_root) =
            extract_fixed_bytes::<BYTES_32_LEN>("BeaconBlockHeader", bytes, cursor)?;
        let (cursor, body_root) =
            extract_fixed_bytes::<BYTES_32_LEN>("BeaconBlockHeader", bytes, cursor)?;

        if cursor != BEACON_BLOCK_HEADER_BYTES_LEN {
            return Err(TypesError::InvalidLength {
                structure: "BeaconBlockHeader".into(),
                expected: BEACON_BLOCK_HEADER_BYTES_LEN,
                actual: cursor,
            });
        }

        Ok(Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        })
    }
}

impl Merkleized for BeaconBlockHeader {
    fn hash_tree_root(&self) -> Result<HashValue, CryptoError> {
        let slot_root = HashValue::new(u64_to_bytes32(self.slot));

        let proposer_index_root = HashValue::new(u64_to_bytes32(self.proposer_index));

        let parent_root = HashValue::new(self.parent_root);

        let state_root = HashValue::new(self.state_root);

        let body_root = HashValue::new(self.body_root);

        let leaves = vec![
            slot_root,
            proposer_index_root,
            parent_root,
            state_root,
            body_root,
        ];

        merkle_root(DataType::Struct(leaves))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use std::env::current_dir;
    use std::fs;
    use tree_hash::TreeHash;
    use tree_hash_derive::TreeHash;

    #[derive(TreeHash)]
    pub(crate) struct BeaconBlockHeaderTreeHash {
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body_root: Bytes32,
    }

    impl From<BeaconBlockHeader> for BeaconBlockHeaderTreeHash {
        fn from(header: BeaconBlockHeader) -> Self {
            Self {
                slot: header.slot,
                proposer_index: header.proposer_index,
                parent_root: header.parent_root,
                state_root: header.state_root,
                body_root: header.body_root,
            }
        }
    }

    #[test]
    fn test_ssz_serde() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/BeaconBlockHeaderDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let beacon_block_header = BeaconBlockHeader::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = beacon_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }

    #[test]
    fn test_beacon_block_hash_tree_root() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/BeaconBlockHeaderDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let beacon_block_header = BeaconBlockHeader::from_ssz_bytes(&test_bytes).unwrap();

        // Hash for custom implementation
        let hash_tree_root = beacon_block_header.hash_tree_root().unwrap();

        // Hash for lighthouse implementation
        let beacon_block_header_tree_hash =
            BeaconBlockHeaderTreeHash::from(beacon_block_header).tree_hash_root();

        assert_eq!(hash_tree_root.hash(), beacon_block_header_tree_hash.0);
    }
}
