// SPDX-License-Identifier: Apache-2.0, MIT

use crate::crypto::hash::{HashValue, HASH_LENGTH};
use crate::types::epoch_state::EpochState;
use crate::types::error::TypesError;
use crate::types::{Round, Version};
use bytes::{Buf, BufMut, BytesMut};
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Eq, CopyGetters, Getters, Serialize, Deserialize)]
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    #[getset(get_copy = "pub")]
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
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

    /// The epoch after this block committed
    pub fn next_block_epoch(&self) -> u64 {
        self.next_epoch_state()
            .as_ref()
            .map_or(self.epoch(), |e| e.epoch)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u64_le(self.epoch);
        bytes.put_u64_le(self.round);
        bytes.put_slice(&self.id.to_vec());
        bytes.put_slice(&self.executed_state_id.to_vec());
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

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let epoch = bytes.get_u64_le();
        let round = bytes.get_u64_le();

        let id = HashValue::from_slice(bytes.chunk().get(..HASH_LENGTH).ok_or_else(|| {
            TypesError::DeserializationError {
                structure: String::from("BlockInfo"),
                source: "Not enough data for id".into(),
            }
        })?)
        .map_err(|e| TypesError::DeserializationError {
            structure: String::from("BlockInfo"),
            source: e.into(),
        })?;

        bytes.advance(HASH_LENGTH); // Advance the buffer by the size of HashValue

        let executed_state_id =
            HashValue::from_slice(bytes.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                TypesError::DeserializationError {
                    structure: String::from("BlockInfo"),
                    source: "Not enough data for executed_state_id".into(),
                }
            })?)
            .map_err(|e| TypesError::DeserializationError {
                structure: String::from("BlockInfo"),
                source: e.into(),
            })?;

        bytes.advance(HASH_LENGTH); // Advance the buffer by the size of HashValue

        let version = bytes.get_u64_le();
        let timestamp_usecs = bytes.get_u64_le();
        println!("cycle-tracker-start: epoch_state_from_bytes");
        let next_epoch_state = match bytes.get_u8() {
            1 => Some(EpochState::from_bytes(bytes.chunk()).map_err(|e| {
                TypesError::DeserializationError {
                    structure: String::from("BlockInfo"),
                    source: e.into(),
                }
            })?),
            _ => None,
        };
        println!("cycle-tracker-end: epoch_state_from_bytes");

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
}

#[cfg(test)]
mod test {
    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_block_info() {
        use super::*;
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::NBR_VALIDATORS;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

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
