// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Block module
//!
//! This module contains the data structures used by the Light Client to store block-related
//! data. It is divided in two main modules, `consensus` and `execution`, each with its own
//! specific functionality.
//!
//! ## Sub-modules
//!
//! - `consensus`: This module contains the data structures related to consensus-related blocks.
//! - `execution`: This module contains the data structures related to execution-related blocks.
//!
//! For more detailed information, users should refer to the specific documentation for each sub-module.

use crate::crypto::error::CryptoError;
use crate::crypto::hash::HashValue;
use crate::deserialization_error;
use crate::merkle::utils::{merkle_root, DataType};
use crate::merkle::Merkleized;
use crate::types::block::consensus::{BeaconBlockHeader, BEACON_BLOCK_HEADER_BYTES_LEN};
use crate::types::block::execution::{
    ExecutionBlockHeader, ExecutionBranch, EXECUTION_BRANCH_NBR_SIBLINGS,
    EXECUTION_HEADER_BASE_BYTES_LEN,
};
use crate::types::error::TypesError;
use crate::types::utils::{extract_u32, OFFSET_BYTE_LENGTH};
use crate::types::BYTES_32_LEN;
use getset::Getters;

pub mod consensus;
pub mod execution;

/// Length in bytes of a LightClientHeader.
pub const LIGHT_CLIENT_HEADER_BASE_BYTES_LEN: usize = BEACON_BLOCK_HEADER_BYTES_LEN
    + OFFSET_BYTE_LENGTH
    + EXECUTION_HEADER_BASE_BYTES_LEN
    + EXECUTION_BRANCH_NBR_SIBLINGS * BYTES_32_LEN;

/// From [the Capella specifications](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/capella/light-client/sync-protocol.md#modified-lightclientheader).
#[derive(Debug, Clone, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct LightClientHeader {
    beacon: BeaconBlockHeader,
    execution: ExecutionBlockHeader,
    execution_branch: ExecutionBranch,
}

impl Merkleized for LightClientHeader {
    fn hash_tree_root(&self) -> Result<HashValue, CryptoError> {
        let beacon_root = self.beacon.hash_tree_root()?;
        let execution_root = self.execution.hash_tree_root()?;

        let leaves = self
            .execution_branch
            .iter()
            .map(HashValue::from_slice)
            .collect::<Result<Vec<_>, _>>()?;

        // Compute the root of the Merkle tree
        let execution_branch_root = merkle_root(DataType::List(leaves))?;

        let leaves = vec![beacon_root, execution_root, execution_branch_root];

        merkle_root(DataType::Struct(leaves))
    }
}

impl LightClientHeader {
    /// Serialize a `LightClientHeader` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `LightClientHeader` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Serialize the beacon block header
        bytes.extend(self.beacon.to_ssz_bytes());

        // Set offset for execution block header
        let offset =
            BEACON_BLOCK_HEADER_BYTES_LEN + 4 + EXECUTION_BRANCH_NBR_SIBLINGS * BYTES_32_LEN;
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());

        // Serialize the execution branch
        for branch in &self.execution_branch {
            bytes.extend(branch);
        }

        // Serialize the execution block header
        bytes.extend(self.execution.to_ssz_bytes());

        bytes
    }

    /// Deserialize a `LightClientHeader` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `LightClientHeader` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized `LightClientHeader` data structure or a `TypesError`.
    ///
    /// # Errors
    ///
    /// Returns a `TypesError` if the bytes are not long enough to create a `LightClientHeader`, if
    /// the offset for the execution block header is invalid, or if the deserialization of internal
    /// types throw an error.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < LIGHT_CLIENT_HEADER_BASE_BYTES_LEN {
            return Err(TypesError::UnderLength {
                minimum: LIGHT_CLIENT_HEADER_BASE_BYTES_LEN,
                actual: bytes.len(),
                structure: "LightClientHeader".into(),
            });
        }

        // Deserialize the beacon block header
        let cursor = 0;
        let beacon = BeaconBlockHeader::from_ssz_bytes(
            &bytes[cursor..cursor + BEACON_BLOCK_HEADER_BYTES_LEN],
        )?;

        // Deserialize the `ExecutionBlockHeader` offset
        let cursor = cursor + BEACON_BLOCK_HEADER_BYTES_LEN;
        let (cursor, offset) = extract_u32("LightClientHeader", bytes, cursor)?;

        // Deserialize the execution branch
        let execution_branch = (0..EXECUTION_BRANCH_NBR_SIBLINGS)
            .map(|i| {
                let start = cursor + i * BYTES_32_LEN;
                let end = start + BYTES_32_LEN;
                bytes[start..end].try_into()
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()
            .map_err(|err| deserialization_error!("LightClientHeader", err))?
            .try_into()
            .map_err(|_| {
                deserialization_error!(
                    "LightClientHeader",
                    "Could not convert the execution branches to a slice of 4 elements"
                )
            })?;

        let cursor = cursor + EXECUTION_BRANCH_NBR_SIBLINGS * BYTES_32_LEN;

        // Check offset
        if cursor != offset as usize {
            return Err(deserialization_error!(
                "LightClientHeader",
                "Invalid offset for execution"
            ));
        }

        // Deserialize the execution block header
        let execution = ExecutionBlockHeader::from_ssz_bytes(&bytes[cursor..])?;

        let deserialized_bytes_len =
            cursor + EXECUTION_HEADER_BASE_BYTES_LEN + execution.extra_data().len();

        if deserialized_bytes_len != bytes.len() {
            return Err(TypesError::OverLength {
                maximum: deserialized_bytes_len,
                actual: bytes.len(),
                structure: "LightClientHeader".into(),
            });
        }

        Ok(Self {
            beacon,
            execution,
            execution_branch,
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::types::block::consensus::test::BeaconBlockHeaderTreeHash;
    use crate::types::block::execution::test::ExecutionBlockHeaderTreeHash;
    use anyhow::anyhow;
    use ssz_types::FixedVector;
    use std::env::current_dir;
    use std::fs;
    use tree_hash::TreeHash;
    use tree_hash_derive::TreeHash;

    // From https://github.com/sigp/lighthouse/blob/stable/consensus/types/src/light_client_header.rs#L47-L66
    #[derive(TreeHash)]
    pub(crate) struct LightClientHeaderTreeHash {
        beacon: BeaconBlockHeaderTreeHash,
        execution: ExecutionBlockHeaderTreeHash,
        execution_branch: FixedVector<[u8; 32], ssz_types::typenum::U4>,
    }

    impl TryFrom<LightClientHeader> for LightClientHeaderTreeHash {
        type Error = anyhow::Error;

        fn try_from(header: LightClientHeader) -> Result<Self, Self::Error> {
            Ok(Self {
                beacon: header.beacon.into(),
                execution: header.execution.try_into()?,
                execution_branch: FixedVector::new(header.execution_branch.to_vec())
                    .map_err(|_| anyhow!("Failed to convert execution branch"))?,
            })
        }
    }

    #[test]
    fn test_ssz_serde() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientHeaderDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let light_client_header = LightClientHeader::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = light_client_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }

    #[test]
    fn test_light_client_header_hash_tree_root() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientHeaderDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let light_client_header = LightClientHeader::from_ssz_bytes(&test_bytes).unwrap();

        let hash_tree_root = light_client_header.hash_tree_root().unwrap();

        let tree_hash_root = LightClientHeaderTreeHash::try_from(light_client_header)
            .unwrap()
            .tree_hash_root();

        assert_eq!(hash_tree_root.hash(), tree_hash_root.0);
    }
}
