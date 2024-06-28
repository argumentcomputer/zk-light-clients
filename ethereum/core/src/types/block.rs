// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use crate::types::Bytes32;
use getset::Getters;

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
    /// Create a new `BeaconBlockHeader`.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot number of the block.
    /// * `proposer_index` - The validator registry index of the validator who proposed the block.
    /// * `parent_root` - The hash of the parent block's header.
    /// * `state_root` - The hash of the beacon state at the start of the block.
    /// * `body_root` - The hash representing the block body.
    ///
    /// # Returns
    ///
    /// A new `BeaconBlockHeader`.
    pub const fn new(
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body_root: Bytes32,
    ) -> Self {
        Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        }
    }
}
