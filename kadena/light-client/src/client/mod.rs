// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Client module
//!
//! This module contains the client for the light client. It is the entrypoint for any needed remote call.
//!
//! ## Sub-modules
//!
//! - `chainweb`: The Chainweb Client is responsible for fetching the data from
//!     the Kadena chain.

use crate::client::chainweb::ChainwebClient;
use crate::client::error::ClientError;
use kadena_lc_core::types::header::layer::ChainwebLayerHeader;

pub(crate) mod chainweb;
pub mod error;
mod utils;

/// The client for the light client. It is the entrypoint for any needed remote call.
#[derive(Debug, Clone)]
pub struct Client {
    chainweb_client: ChainwebClient,
}

impl Client {
    /// Create a new client with the given addresses.
    ///
    /// # Arguments
    ///
    /// * `chainweb_node_address: ` - The address of the Checkpoint Provider API.
    ///
    /// # Returns
    ///
    /// A new `Client`.
    pub fn new(chainweb_node_address: &str) -> Self {
        Self {
            chainweb_client: ChainwebClient::new(chainweb_node_address),
        }
    }

    /// Test the connection to all the endpoints.
    ///
    /// # Returns
    ///
    /// A result indicating whether the connections were successful.
    pub async fn test_endpoints(&self) -> Result<(), ClientError> {
        tokio::try_join!(self.chainweb_client.test_endpoint(),)?;

        Ok(())
    }

    pub async fn get_layer_block_headers(
        &self,
        target_block: usize,
        block_window: usize,
    ) -> Result<Vec<ChainwebLayerHeader>, ClientError> {
        self.chainweb_client
            .get_layer_block_headers(target_block, block_window)
            .await
    }
}
