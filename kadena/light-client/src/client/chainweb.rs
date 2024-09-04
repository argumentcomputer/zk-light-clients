// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Chainweb client module
//!
//! This module contains the client for the Chainweb Node API. It is responsible for fetching the data
//! necessary to prove sync committee changes and value inclusion in the state of the Ethereum network.
//!
//! It maintains an internal HTTP client to handle communication with the Beacon Node.

use crate::client::error::ClientError;
use crate::client::utils::test_connection;
use crate::types::chainweb::BlockHeaderResponse;
use getset::Getters;
use kadena_lc_core::types::header::KadenaHeaderRaw;
use reqwest::header::ACCEPT;
use reqwest::Client;

const CHAINWEB_API_VERSION: &str = "0.0";

/// An internal client to handle communication with a Chainweb Node.
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub(crate)")]
pub(crate) struct ChainwebClient {
    /// The address of the Chainweb Node API.
    chainweb_node_address: String,
    /// The inner HTTP client.
    inner: Client,
}

impl ChainwebClient {
    /// Create a new client with the given address.
    ///
    /// # Arguments
    ///
    /// * `chainweb_node_address` - The address of the Chainweb Node API.
    ///
    /// # Returns
    ///
    /// A new `ChainwebClient`.
    pub(crate) fn new(chainweb_node_address: &str) -> Self {
        Self {
            chainweb_node_address: chainweb_node_address.to_string(),
            inner: Client::new(),
        }
    }

    /// Test the connection to the chainweb node.
    ///
    /// # Returns
    ///
    /// A result indicating whether the connection was successful.
    pub(crate) async fn test_endpoint(&self) -> Result<(), ClientError> {
        // Try to connect to the chainweb node server
        test_connection(&self.chainweb_node_address).await
    }

    /// `get_finality_update` makes an HTTP request to the Chainweb Node API to get the finality update.
    /// It fetches the finality update for the latest finalized header.
    ///
    /// # Returns
    ///
    /// The finality update.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub(crate) async fn get_block_headers(
        &self,
        target_block: usize,
        block_window: usize,
    ) -> Result<Vec<KadenaHeaderRaw>, ClientError> {
        // Format the endpoint for the call
        let url = format!(
            "{}/{CHAINWEB_API_VERSION}/mainnet01/chain/0/header",
            self.chainweb_node_address
        );

        // Send the HTTP request
        let response = self
            .inner
            .get(&url)
            .header(ACCEPT, "application/json")
            .query(&[
                ("minheight", target_block - block_window),
                ("maxheight", target_block + block_window),
            ])
            .send()
            .await
            .map_err(|err| ClientError::Request {
                endpoint: url.clone(),
                source: Box::new(err),
            })?;

        if !response.status().is_success() {
            return Err(ClientError::Request {
                endpoint: url,
                source: format!(
                    "Request not successful, got HTTP code {}",
                    response.status().as_str()
                )
                .into(),
            });
        }

        // Deserialize the response
        let response: BlockHeaderResponse =
            response.json().await.map_err(|err| ClientError::Request {
                endpoint: url.clone(),
                source: Box::new(err),
            })?;

        response.try_into().map_err(|err| ClientError::Response {
            endpoint: url.clone(),
            source: Box::new(err),
        })
    }
}
