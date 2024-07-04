// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Client module
//!
//! This module contains the client for the light client. It is the entrypoint for any needed remote call.
//! The client is composed of two main components: the Beacon Client and the Checkpoint Client.
//!
//! ## Sub-modules
//!
//! - `beacon`: The Beacon Client is responsible for fetching the data necessary to prove sync committee changes
//!   and value inclusion in the state of the Ethereum network.
//! - `checkpoint`: The Checkpoint Client is responsible for fetching the data of the latest finalized block root.

use crate::client::beacon::BeaconClient;
use crate::client::checkpoint::CheckpointClient;
use crate::client::error::ClientError;
use crate::types::beacon::bootstrap::Bootstrap;
use crate::types::checkpoint::Checkpoint;

pub(crate) mod beacon;
pub(crate) mod checkpoint;
pub mod error;

/// The client for the light client. It is the entrypoint for any needed remote call.
#[derive(Debug, Clone)]
pub struct Client {
    beacon_client: BeaconClient,
    checkpoint_client: CheckpointClient,
}

impl Client {
    /// Create a new client with the given addresses.
    ///
    /// # Arguments
    ///
    /// * `checkpoint_provider_address` - The address of the Checkpoint Provider API.
    /// * `beacon_node_address` - The address of the Beacon Node API.
    ///
    /// # Returns
    ///
    /// A new `Client`.
    pub fn new(checkpoint_provider_address: &str, beacon_node_address: &str) -> Self {
        Self {
            beacon_client: BeaconClient::new(beacon_node_address),
            checkpoint_client: CheckpointClient::new(checkpoint_provider_address),
        }
    }

    /// `get_bootstrap_data` makes an HTTP request to the Beacon Node API to get the bootstrap data.
    ///
    /// # Arguments
    ///
    /// * `checkpoint` - The checkpoint to get the bootstrap data for.
    ///
    /// # Returns
    ///
    /// The bootstrap data.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn get_bootstrap_data(&self, checkpoint: &str) -> Result<Bootstrap, ClientError> {
        self.beacon_client.get_bootstrap_data(checkpoint).await
    }

    /// `get_checkpoint` makes an HTTP request to the Checkpoint Provider API to get the checkpoint
    /// at the specified slot. If no particular slot is specified, returns the latest checkpoint.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot to get the checkpoint for.
    ///
    /// # Returns
    ///
    /// The fetched checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn get_checkpoint(&self, slot: Option<u64>) -> Result<Checkpoint, ClientError> {
        self.checkpoint_client.get_checkpoint(slot).await
    }
}
