// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::HashValue;
use crate::types::epoch_state::EpochState;
use crate::types::{Round, Version};
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, PartialEq, Eq, CopyGetters, Getters, Serialize, Deserialize)]
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
    pub fn new(
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
}
