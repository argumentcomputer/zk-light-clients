// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Chainweb client module
//!
//! This module contains the client for the Chainweb Node API. It is responsible for fetching the data
//! necessary to prove produced work of the Chainweb network and inclusion of
//! data in its state.
//!
//! It maintains an internal HTTP client to handle communication with the Chainweb Node.

use crate::client::error::ClientError;
use crate::client::utils::test_connection;
use crate::types::chainweb::{BlockHeaderResponse, SpvResponse};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;
use kadena_lc_core::merkle::spv::Spv;
use kadena_lc_core::types::error::TypesError;
use kadena_lc_core::types::header::chain::KadenaHeaderRaw;
use kadena_lc_core::types::header::layer::ChainwebLayerHeader;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Body, Client};
use serde_json::json;
use std::sync::Arc;
use tokio::task::JoinSet;

/// The version of the Chainweb API.
const CHAINWEB_API_VERSION: &str = "0.0";
/// The number of chains in the Chainweb network.
const CHAINWEB_CHAIN_COUNT: usize = 20;

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

    /// Test the connection to the Chainweb node.
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
    /// # Arguments
    ///
    /// * `target_block` - The target block to get the headers for.
    /// * `block_window` - The number of blocks to get before and after the target block.
    ///
    /// # Returns
    ///
    /// The layer block headers.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub(crate) async fn get_layer_block_headers(
        &self,
        target_block: usize,
        block_window: usize,
    ) -> Result<Vec<ChainwebLayerHeader>, ClientError> {
        let mut set = JoinSet::new();

        // Spawn tasks for fetching block headers for each chain (0 to 19).
        for chain in 0..CHAINWEB_CHAIN_COUNT {
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
        let mut response: Vec<Vec<KadenaHeaderRaw>> =
            vec![vec![KadenaHeaderRaw::default(); CHAINWEB_CHAIN_COUNT]; 1 + block_window * 2];

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

                    if chain >= CHAINWEB_CHAIN_COUNT {
                        return Err(ClientError::Response {
                            endpoint: "get_layer_block_headers".to_string(),
                            source: format!("Invalid chain number: {}", chain).into(),
                        });
                    }

                    for (position, header) in headers.into_iter().enumerate() {
                        response[position][chain] = header;
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

        let layer_headers = response
            .into_iter()
            .map(|headers| {
                // We can unwrap here as if the previous code section did not return an
                // error we should have at least one header per height
                let height = u64::from_le_bytes(
                    *headers
                        .first()
                        .expect("Should be able to access element 0 of slice")
                        .height(),
                );
                ChainwebLayerHeader::new(height, headers).map_err(|err| ClientError::Response {
                    endpoint: "get_layer_block_headers".to_string(),
                    source: Box::new(err),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(layer_headers)
    }

    /// `get_spv` makes an HTTP request to the Chainweb Node API to get an SPV proof.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to get the SPV proof for.
    /// * `request_key` - The request key for the SPV proof.
    ///
    /// # Returns
    ///
    /// The SPV proof.
    pub(crate) async fn get_spv(
        &self,
        chain: u32,
        request_key: String,
    ) -> Result<Spv, ClientError> {
        // Format the endpoint for the call
        let url = format!(
            "{}/chainweb/{CHAINWEB_API_VERSION}/mainnet01/chain/{chain}/pact/spv",
            self.chainweb_node_address,
        );

        let payload = json!(
            {
                "requestKey": request_key,
                "targetChainId": "0"
            }
        );

        // Send the HTTP request
        let response = self
            .inner
            .post(&url)
            .header(CONTENT_TYPE, "application/json;charset=utf-8")
            .body(Body::from(payload.to_string()))
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
        let encoded_spv_response: String =
            response.json().await.map_err(|err| ClientError::Request {
                endpoint: url.clone(),
                source: Box::new(err),
            })?;

        let decoded_spv_response = URL_SAFE_NO_PAD
            .decode(encoded_spv_response.as_bytes())
            .map_err(|err| ClientError::Response {
                endpoint: url.clone(),
                source: err.into(),
            })?;

        let spv_response: SpvResponse =
            serde_json::from_slice(&decoded_spv_response).map_err(|err| ClientError::Response {
                endpoint: url.clone(),
                source: err.into(),
            })?;

        spv_response
            .try_into()
            .map_err(|err: TypesError| ClientError::Response {
                endpoint: url,
                source: err.into(),
            })
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
/// The block headers.
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
        "{}/chainweb/{CHAINWEB_API_VERSION}/mainnet01/chain/{chain}/header",
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
