// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Execution Block module
//!
//! This module contains the types and utilities necessary to represent the data in an execution block.

use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::OFFSET_BYTE_LENGTH;
use crate::types::{Address, Bytes32, ADDRESS_BYTES_LEN, BYTES_32_LEN, U64_LEN};

/// Number of leaf values on a given execution path.
///
/// From [the Capella specifications](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/capella/light-client/sync-protocol.md#custom-types).
pub const EXECUTION_PROOF_SIZE: usize = 4;

/// Path in the tree to the execution payload in the beacon block body.
pub type ExecutionBranch = [Bytes32; EXECUTION_PROOF_SIZE];

/// Size of the logs bloom in an execution block header.
pub const LOGS_BLOOM_BYTES_LEN: usize = 256;

/// Logs bloom in an execution header.
pub type LogsBloom = [u8; LOGS_BLOOM_BYTES_LEN];

/// Minimal size in bytes of an execution header.
pub const EXECUTION_HEADER_BASE_BYTES_LEN: usize =
    BYTES_32_LEN * 8 + U64_LEN * 6 + ADDRESS_BYTES_LEN + LOGS_BLOOM_BYTES_LEN + OFFSET_BYTE_LENGTH;

/// Max extra_data size, from [the Bellatrix specifications](https://github.com/ethereum/consensus-specs/blob/v1.4.0/presets/mainnet/bellatrix.yaml).
pub const MAX_EXTRA_DATA_BYTES_LEN: usize = BYTES_32_LEN;

/// `ExecutionBlockHeader` represents the header of an execution block.
#[derive(Debug, Clone)]
pub struct ExecutionBlockHeader {
    parent_hash: Bytes32,
    fee_recipient: Address,
    state_root: Bytes32,
    receipts_root: Bytes32,
    logs_bloom: LogsBloom,
    prev_randao: Bytes32,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: Vec<u8>,
    base_fee_per_gas: Bytes32,
    block_hash: Bytes32,
    transactions_root: Bytes32,
    withdrawals_root: Bytes32,
    blob_gas_used: u64,
    excess_blob_gas: u64,
}

impl ExecutionBlockHeader {
    /// Serialize an `ExecutionBlockHeader` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `ExecutionBlockHeader` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.fee_recipient);
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.receipts_root);
        bytes.extend_from_slice(&self.logs_bloom);
        bytes.extend_from_slice(&self.prev_randao);
        bytes.extend_from_slice(&self.block_number.to_le_bytes());
        bytes.extend_from_slice(&self.gas_limit.to_le_bytes());
        bytes.extend_from_slice(&self.gas_used.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        let offset = 436 + 4 + 144; // Fixed-size length + offset size for extra_data + rest of fixed-size data
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());

        bytes.extend_from_slice(&self.base_fee_per_gas);
        bytes.extend_from_slice(&self.block_hash);
        bytes.extend_from_slice(&self.transactions_root);
        bytes.extend_from_slice(&self.withdrawals_root);
        bytes.extend_from_slice(&self.blob_gas_used.to_le_bytes());
        bytes.extend_from_slice(&self.excess_blob_gas.to_le_bytes());

        bytes.extend_from_slice(&self.extra_data);

        bytes
    }

    /// Deserialize an `ExecutionBlockHeader` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `ExecutionBlockHeader` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized `ExecutionBlockHeader` data structure or a `TypesError`.
    ///
    /// # Errors
    ///
    /// Returns a `TypesError` if the bytes are not long enough to create an `ExecutionBlockHeader`, if
    /// the offset for the extra data is invalid, or if the deserialization of internal types throw an error.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < EXECUTION_HEADER_BASE_BYTES_LEN {
            return Err(TypesError::UnderLength {
                minimum: EXECUTION_HEADER_BASE_BYTES_LEN,
                actual: bytes.len(),
                structure: "ExecutionBlockHeader".into(),
            });
        } else if bytes.len() > EXECUTION_HEADER_BASE_BYTES_LEN + MAX_EXTRA_DATA_BYTES_LEN {
            return Err(TypesError::OverLength {
                maximum: EXECUTION_HEADER_BASE_BYTES_LEN + MAX_EXTRA_DATA_BYTES_LEN,
                actual: bytes.len(),
                structure: "ExecutionBlockHeader".into(),
            });
        }

        let cursor = 0;
        let parent_hash = bytes[cursor..BYTES_32_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid parent_hash bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let fee_recipient = bytes[cursor..cursor + ADDRESS_BYTES_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid fee_recipient bytes"))?;

        let cursor = cursor + ADDRESS_BYTES_LEN;
        let state_root = bytes[cursor..cursor + BYTES_32_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid state_root bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let receipts_root = bytes[cursor..cursor + BYTES_32_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid receipts_root bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let logs_bloom = bytes[cursor..cursor + LOGS_BLOOM_BYTES_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid logs_bloom bytes"))?;

        let cursor = cursor + LOGS_BLOOM_BYTES_LEN;
        let prev_randao = bytes[cursor..cursor + BYTES_32_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid prev_randao bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let block_number = u64::from_le_bytes(
            bytes[cursor..cursor + U64_LEN]
                .try_into()
                .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid block_number bytes"))?,
        );

        let cursor = cursor + U64_LEN;
        let gas_limit = u64::from_le_bytes(
            bytes[cursor..cursor + U64_LEN]
                .try_into()
                .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid gas_limit bytes"))?,
        );

        let cursor = cursor + U64_LEN;
        let gas_used = u64::from_le_bytes(
            bytes[cursor..cursor + U64_LEN]
                .try_into()
                .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid gas_used bytes"))?,
        );

        let cursor = cursor + U64_LEN;
        let timestamp = u64::from_le_bytes(
            bytes[cursor..cursor + U64_LEN]
                .try_into()
                .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid timestamp bytes"))?,
        );

        let cursor = cursor + U64_LEN;
        let offset = u32::from_le_bytes(
            bytes[cursor..cursor + OFFSET_BYTE_LENGTH]
                .try_into()
                .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid offset bytes"))?,
        ) as usize;

        let cursor = cursor + OFFSET_BYTE_LENGTH;
        let base_fee_per_gas = bytes[cursor..cursor + BYTES_32_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid base_fee_per_gas bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let block_hash = bytes[472..504]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid block_hash bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let transactions_root = bytes[cursor..cursor + BYTES_32_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid transactions_root bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let withdrawals_root = bytes[cursor..cursor + BYTES_32_LEN]
            .try_into()
            .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid withdrawals_root bytes"))?;

        let cursor = cursor + BYTES_32_LEN;
        let blob_gas_used =
            u64::from_le_bytes(bytes[cursor..cursor + U64_LEN].try_into().map_err(|_| {
                serde_error!("ExecutionBlockHeader", "Invalid blob_gas_used bytes")
            })?);

        let cursor = cursor + U64_LEN;
        let excess_blob_gas =
            u64::from_le_bytes(bytes[cursor..cursor + U64_LEN].try_into().map_err(|_| {
                serde_error!("ExecutionBlockHeader", "Invalid excess_blob_gas bytes")
            })?);

        let cursor = cursor + U64_LEN;

        if cursor != offset {
            return Err(serde_error!(
                "ExecutionBlockHeader",
                "Invalid offset for extra_data"
            ));
        }

        let extra_data = bytes[offset..].to_vec();

        if extra_data.len() > MAX_EXTRA_DATA_BYTES_LEN {
            return Err(serde_error!(
                "ExecutionBlockHeader",
                "Extra data exceeds maximum length"
            ));
        }

        Ok(ExecutionBlockHeader {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions_root,
            withdrawals_root,
            blob_gas_used,
            excess_blob_gas,
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
            .join("../test-assets/ExecutionPayloadHeaderDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let execution_block_header = ExecutionBlockHeader::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = execution_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
