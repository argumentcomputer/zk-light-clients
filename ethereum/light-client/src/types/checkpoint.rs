// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Checkpoint module
//!
//! This module contains the data structures used by the Checkpoint service. The checkpoints are the
//! latest finalized block root that are accessed through a trusted service.
//!
//! A list of available services to fetch this data can be found [on _eth-clients.github.io_](https://eth-clients.github.io/checkpoint-sync-endpoints/).

use getset::Getters;
use serde::Deserialize;

/// `SlotsResponse` represents the response from the `/slots` endpoint.
#[derive(Debug, Clone, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct SlotsResponse {
    data: Slots,
}

/// `Slots` represents the checkpoints in the response from the `/slots` endpoint.
#[derive(Debug, Clone, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct Slots {
    slots: Vec<Checkpoint>,
}

/// `Checkpoint` represents a checkpoint in the response from the `/slots` endpoint.
///
/// # Note
///
/// There are two variants to this data type as the response from the `/slots` endpoint can
/// contain a checkpoint with or without a block root. Most likely a bug from the provider part.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Checkpoint {
    WithRoot(CheckpointWithRoot),
    WithoutRoot(CheckpointWithoutRoot),
}

impl Checkpoint {
    pub fn slot(&self) -> &String {
        match self {
            Checkpoint::WithRoot(checkpoint) => checkpoint.slot(),
            Checkpoint::WithoutRoot(checkpoint) => checkpoint.slot(),
        }
    }

    pub fn block_root(&self) -> Option<&String> {
        match self {
            Checkpoint::WithRoot(checkpoint) => Some(checkpoint.block_root()),
            Checkpoint::WithoutRoot(_) => None,
        }
    }
}

/// `CheckpointWithRoot` represents a checkpoint with the root for the block and state merkle trees.
#[derive(Debug, Clone, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct CheckpointWithRoot {
    slot: String,
    block_root: String,
    state_root: String,
    epoch: u64,
    time: Time,
}

/// `Time` represents the start and end time of a checkpoint.
#[derive(Debug, Clone, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct Time {
    start_time: String,
    end_time: String,
}

/// `CheckpointWithoutRoot` represents a checkpoint without the root for the block and state merkle trees.
///
/// # Note
///
/// This should not happen and is most likely a bug on the provider side.
#[derive(Debug, Clone, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct CheckpointWithoutRoot {
    slot: String,
    epoch: u64,
    time: Time,
}
