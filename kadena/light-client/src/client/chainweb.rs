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
use std::sync::Arc;
use tokio::task::JoinSet;

const CHAINWEB_API_VERSION: &str = "0.0";

/// An internal client to handle communication with a Chainweb Node.
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub(crate)")]
pub(crate) struct ChainwebClient {
    /// The address of the Chainweb Node API.
    chainweb_node_address: Arc<String>,
    /// The inner HTTP client.
    inner: Arc<Client>,
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
            chainweb_node_address: Arc::new(chainweb_node_address.to_string()),
            inner: Arc::new(Client::new()),
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

    /// `get_layer_block_headers` leverages `get_block_headers` to
    /// get the block headers for each chain of the Chainweb network (0 to 19).
    ///
    /// # Returns
    ///
    /// The finality update.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub(crate) async fn get_layer_block_headers(
        &self,
        target_block: usize,
        block_window: usize,
    ) -> Result<Vec<Vec<KadenaHeaderRaw>>, ClientError> {
        let mut set = JoinSet::new();

        // Spawn tasks for fetching block headers for each chain (0 to 19).
        for chain in 0..20 {
            let client = self.inner.clone();
            let address = self.chainweb_node_address.clone();
            set.spawn(get_block_headers(
                client,
                address,
                target_block,
                block_window,
                chain,
            ));
        }

        // Initialize a vector with 20 elements (for chains 0 to 19), each holding the result (Vec<KadenaHeaderRaw>).
        let mut output: Vec<Vec<KadenaHeaderRaw>> = vec![vec![KadenaHeaderRaw::default(); 20]; 7];

        // Collect results as they complete.
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(headers)) => {
                    if headers.len() != 1 + block_window * 2 {
                        return Err(ClientError::Response {
                            endpoint: "get_layer_block_headers".to_string(),
                            source: format!(
                                "Expected {} headers, got {}",
                                1 + block_window * 2,
                                headers.len()
                            )
                            .into(),
                        });
                    }

                    let chain = u32::from_le_bytes(
                        *headers
                            .first()
                            .expect("Should be able to access element 0 of slice")
                            .chain(),
                    ) as usize;

                    for (position, header) in headers.into_iter().enumerate() {
                        output[position][chain] = header;
                    }
                }
                Ok(Err(err)) => {
                    // Return the first encountered error
                    return Err(ClientError::Request {
                        endpoint: "get_layer_block_headers".to_string(),
                        source: Box::new(err),
                    });
                }
                Err(err) => {
                    // Handle join error (e.g., task panicked)
                    return Err(ClientError::Request {
                        endpoint: "get_layer_block_headers".to_string(),
                        source: Box::new(err),
                    });
                }
            }
        }

        Ok(output)
    }
}

/// `get_block_headers` makes an HTTP request to the Chainweb Node API
/// to get the block headers for a particular chain.
///
///  # Arguments
///
/// * `target_block` - The target block to get the headers for.
/// * `block_window` - The number of blocks to get before and after the target block.
/// * `chain` - The chain to get the headers for.
///
/// # Returns
///
/// The finality update.
///
/// # Errors
///
/// Returns an error if the request fails or the response is not successful or properly formatted.
pub(crate) async fn get_block_headers(
    client: Arc<Client>,
    chainweb_node_address: Arc<String>,
    target_block: usize,
    block_window: usize,
    chain: usize,
) -> Result<Vec<KadenaHeaderRaw>, ClientError> {
    // Format the endpoint for the call
    let url = format!(
        "{}/{CHAINWEB_API_VERSION}/mainnet01/chain/{chain}/header",
        chainweb_node_address
    );

    // Send the HTTP request
    let response = client
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
