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

use crate::serde_error;
use crate::types::block::consensus::{BeaconBlockHeader, BEACON_BLOCK_HEADER_BYTES_LEN};
use crate::types::block::execution::{
    ExecutionBlockHeader, ExecutionBranch, EXECUTION_HEADER_BASE_BYTES_LEN, EXECUTION_PROOF_SIZE,
};
use crate::types::error::TypesError;
use crate::types::utils::OFFSET_BYTE_LENGTH;
use crate::types::BYTES_32_LEN;

pub mod consensus;
pub mod execution;

/// Length in bytes of a LightClientHeader.
pub const LIGHT_CLIENT_HEADER_BASE_BYTES_LEN: usize = BEACON_BLOCK_HEADER_BYTES_LEN
    + EXECUTION_HEADER_BASE_BYTES_LEN
    + EXECUTION_PROOF_SIZE * BYTES_32_LEN;

/// From [the Capella specifications](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/capella/light-client/sync-protocol.md#modified-lightclientheader).
#[derive(Debug, Clone)]
pub struct LightClientHeader {
    beacon: BeaconBlockHeader,
    execution: ExecutionBlockHeader,
    execution_branch: ExecutionBranch,
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
        let offset = BEACON_BLOCK_HEADER_BYTES_LEN + 4 + EXECUTION_PROOF_SIZE * BYTES_32_LEN;
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
        let offset = u32::from_le_bytes(
            bytes[cursor..cursor + OFFSET_BYTE_LENGTH]
                .try_into()
                .map_err(|_| serde_error!("LightClientHeader", "Invalid offset bytes"))?,
        ) as usize;

        // Deserialize the execution branch
        let cursor = cursor + OFFSET_BYTE_LENGTH;
        let execution_branch = (0..EXECUTION_PROOF_SIZE)
            .map(|i| {
                let start = cursor + i * BYTES_32_LEN;
                let end = start + BYTES_32_LEN;
                bytes[start..end].try_into()
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()
            .map_err(|err| serde_error!("LightClientHeader", err))?
            .try_into()
            .map_err(|_| {
                serde_error!(
                    "LightClientHeader",
                    "Could not convert the execution branches to a slice of 4 elements"
                )
            })?;

        // Deserialize the execution block header
        let cursor = cursor + EXECUTION_PROOF_SIZE * BYTES_32_LEN;

        if cursor != offset {
            return Err(serde_error!(
                "LightClientHeader",
                "Invalid offset for execution"
            ));
        }

        let execution = ExecutionBlockHeader::from_ssz_bytes(&bytes[cursor..])?;

        Ok(Self {
            beacon,
            execution,
            execution_branch,
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
            .join("../test-assets/LightClientHeaderDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let beacon_block_header = LightClientHeader::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = beacon_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
