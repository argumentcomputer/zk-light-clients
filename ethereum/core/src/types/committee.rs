// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use crate::crypto::sig::PublicKey;
use crate::types::SYNC_COMMITTEE_SIZE;
use getset::Getters;

/// `SyncCommittee` is a committee of validators that are responsible for attesting to the latest
/// block. The sync committee is a subset of the full validator set.
///
/// From [the Altair upgrade specifications](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#synccommittee).
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct SyncCommittee {
    pubkeys: [PublicKey; SYNC_COMMITTEE_SIZE],
    aggregate_pubkey: PublicKey,
}
