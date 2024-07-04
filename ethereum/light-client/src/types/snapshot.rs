// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

//! # Snapshot module
//!
//! This module contains the data structure used to represent the light client's view of the most
//! recent block header that the light client is convinced is securely part of the chain.

use ethereum_lc_core::types::block::LightClientHeader;
use ethereum_lc_core::types::committee::SyncCommittee;
use getset::Getters;

/// `LightClientSnapshot` represents the light client's view of the most recent block header that
/// the light client is convinced is securely part of the chain.
///
/// From [the Altaïr specifications](https://github.com/ethereum/annotated-spec/blob/master/altair/sync-protocol.md#lightclientsnapshot).
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct LightClientSnapshot {
    /// Beacon block header
    header: LightClientHeader,
    /// Latest validated sync committee
    current_sync_committee: SyncCommittee,
    /// Next sync committee
    next_sync_committee: SyncCommittee,
}
