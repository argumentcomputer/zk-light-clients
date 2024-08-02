// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Block Info Module
//!
//! This module provides the `BlockInfo` structure and
//! associated methods for handling block information
//! in the Aptos Light Client.
//!
//! The `BlockInfo` structure represents the metadata
//! of a committed block in the blockchain, including the
//! epoch and round numbers, the block identifier, the root
//! hash of the state after executing this block, the version
//! of the latest transaction, the timestamp when the block
//! was proposed, and  optionally the state of the next epoch.

// SPDX-License-Identifier: Apache-2.0
use crate::crypto::hash::{HashValue, HASH_LENGTH};
use crate::serde_error;
use crate::types::epoch_state::EpochState;
use crate::types::error::TypesError;
use crate::types::utils::U64_SIZE;
use crate::types::{Round, Version};
use bytes::{Buf, BufMut, BytesMut};
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};

/// `BlockInfo` is a structure representing a block in the blockchain.
#[derive(Default, Debug, Clone, PartialEq, Eq, CopyGetters, Getters, Serialize, Deserialize)]
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    #[getset(get_copy = "pub")]
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    #[getset(get_copy = "pub")]
    id: HashValue,
    /// The accumulator root hash after executing this block.
    #[getset(get_copy = "pub")]
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    #[getset(get_copy = "pub")]
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    #[getset(get_copy = "pub")]
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    #[getset(get = "pub")]
    next_epoch_state: Option<EpochState>,
}

impl BlockInfo {
    /// Creates a new `BlockInfo`.
    ///
    /// # Arguments
    ///
    /// * `epoch: u64` - The epoch to which the block belongs.
    /// * `round: Round` - The round in which the consensus protocol was executed.
    /// * `id: HashValue` - The identifier (hash) of the block.
    /// * `executed_state_id: HashValue` - The accumulator root hash after executing this block.
    /// * `version: Version` - The version of the latest transaction after executing this block.
    /// * `timestamp_usecs: u64` - The timestamp this block was proposed by a proposer.
    /// * `next_epoch_state: Option<EpochState>` - An optional field containing the next epoch info.
    ///
    /// # Returns
    ///
    /// A new `BlockInfo`.
    pub const fn new(
        epoch: u64,
        round: Round,
        id: HashValue,
        executed_state_id: HashValue,
        version: Version,
        timestamp_usecs: u64,
        next_epoch_state: Option<EpochState>,
    ) -> Self {
        Self {
            epoch,
            round,
            id,
            executed_state_id,
            version,
            timestamp_usecs,
            next_epoch_state,
        }
    }

    /// Returns the epoch after this block committed.
    ///
    /// # Returns
    ///
    /// The epoch after this block committed.
    pub fn next_block_epoch(&self) -> u64 {
        self.next_epoch_state()
            .as_ref()
            .map_or(self.epoch(), |e| e.epoch)
    }

    /// Converts the `BlockInfo` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `BlockInfo`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u64_le(self.epoch);
        bytes.put_u64_le(self.round);
        bytes.put_slice(self.id.as_ref());
        bytes.put_slice(self.executed_state_id.as_ref());
        bytes.put_u64_le(self.version);
        bytes.put_u64_le(self.timestamp_usecs);
        match &self.next_epoch_state {
            Some(state) => {
                bytes.put_u8(1); // Indicate that there is a next_epoch_state
                bytes.put_slice(&state.to_bytes());
            }
            None => {
                bytes.put_u8(0); // Indicate that there is no next_epoch_state
            }
        }
        bytes.to_vec()
    }

    /// Creates a `BlockInfo` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `BlockInfo`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `BlockInfo` could
    /// be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let epoch_state_size = bytes.len() - 4 * U64_SIZE - 2 * HASH_LENGTH - 1;

        let epoch = bytes.get_u64_le();
        let round = bytes.get_u64_le();

        let id = HashValue::from_slice(
            bytes
                .chunk()
                .get(..HASH_LENGTH)
                .ok_or_else(|| serde_error!("BlockInfo", "Not enough data for id"))?,
        )
        .map_err(|e| serde_error!("BlockInfo", e))?;

        bytes.advance(HASH_LENGTH); // Advance the buffer by the size of HashValue

        let executed_state_id =
            HashValue::from_slice(bytes.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                serde_error!("BlockInfo", "Not enough data for executed_state_id")
            })?)
            .map_err(|e| serde_error!("BlockInfo", e))?;

        bytes.advance(HASH_LENGTH); // Advance the buffer by the size of HashValue

        let version = bytes.get_u64_le();
        let timestamp_usecs = bytes.get_u64_le();

        let next_epoch_state = match bytes.get_u8() {
            1 => {
                let epoch_state =
                    EpochState::from_bytes(bytes.chunk().get(..epoch_state_size).ok_or_else(
                        || serde_error!("BlockInfo", "Not enough data for epoch state"),
                    )?)
                    .map_err(|e| serde_error!("BlockInfo", e))?;
                bytes.advance(epoch_state_size);

                Some(epoch_state)
            }
            _ => None,
        };

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "BlockInfo",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self {
            epoch,
            round,
            id,
            executed_state_id,
            version,
            timestamp_usecs,
            next_epoch_state,
        })
    }

    /// Estimate the size in bytes for  `BlockInfo` from the given bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to estimate the size.
    ///
    /// # Returns
    ///
    /// The estimated size in bytes for the structure.
    ///
    /// # Note
    ///
    /// The `BlockInfo` bytes should start from offset 0 of the slice.
    pub(crate) fn estimate_size_from_bytes(bytes: &[u8]) -> Result<usize, TypesError> {
        let fixed_size = 4 * U64_SIZE + 2 * HASH_LENGTH;

        let has_epoch_state = bytes
            .get(4 * U64_SIZE + 2 * HASH_LENGTH)
            .ok_or_else(|| serde_error!("BlockInfo", "Not enough data for next_epoch_state"))?;

        if *has_epoch_state == 0 {
            return Ok(fixed_size + 1);
        }

        Ok(fixed_size
            + 1
            + EpochState::estimate_size_from_bytes(
                bytes
                    .get(fixed_size + 1..)
                    .ok_or_else(|| serde_error!("BlockInfo", "Not enough data for EpochState"))?,
            )?)
    }
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use proptest::prelude::ProptestConfig;
    use proptest::proptest;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_bytes_conversion_block_info(
            validators in 130..136,
            signers in 95..101
        ) {
            use super::*;
            use crate::aptos_test_utils::wrapper::AptosWrapper;

            let mut aptos_wrapper = AptosWrapper::new(2, validators as usize, signers as usize).unwrap();

            aptos_wrapper.generate_traffic().unwrap();
            aptos_wrapper.commit_new_epoch().unwrap();

            let block_info = aptos_wrapper
                .get_latest_li()
                .unwrap()
                .ledger_info()
                .commit_info()
                .clone();

            let bytes = bcs::to_bytes(&block_info).unwrap();

            let block_info_deserialized = BlockInfo::from_bytes(&bytes).unwrap();
            let block_info_serialized = block_info_deserialized.to_bytes();

            assert_eq!(bytes, block_info_serialized);
        }
    }
}
