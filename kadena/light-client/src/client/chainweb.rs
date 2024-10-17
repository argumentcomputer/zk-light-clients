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
use crate::types::chainweb::{BlockHeaderResponse, PayloadResponse, SpvResponse};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;
use kadena_lc_core::crypto::hash::{HashValue, DIGEST_BYTES_LENGTH};
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
                Ok(Ok(mut headers)) => {
                    if headers.len() > 1 + block_window * 2 {
                        // If the last height in the list has an uncle then we need to fetch its child
                        // to sort it out
                        let mut added_headers_count = 0;
                        let chain = u32::from_le_bytes(
                            *headers
                                .first()
                                .expect("Should be able to access element 0 of slice")
                                .chain(),
                        ) as usize;
                        while headers[headers.len() - 1].height()
                            == headers[headers.len() - 2].height()
                        {
                            // Fetch next block to sort out the uncle
                            let client = self.inner.clone();
                            let address = self.chainweb_node_address.clone();
                            let added_headers = get_block_headers(
                                client,
                                address,
                                (headers[headers.len() - 2].decoded_height() + 1) as usize,
                                0,
                                chain,
                            )
                            .await?;
                            // Add the fetched header to the list
                            headers.extend_from_slice(&added_headers);
                            // Increment the count of added headers
                            added_headers_count += 1;
                        }

                        // Filter out the uncles
                        headers = filter_uncles_chain_headers(
                            headers,
                            1 + block_window * 2 + added_headers_count,
                        )?;

                        // Truncate to the expected length, in case we had
                        // to add some  headers to sort out the uncles
                        headers.truncate(1 + block_window * 2);
                    }

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

    /// `get_payload` makes an HTTP request to the Chainweb Node
    /// API to get the payload for a particular hash.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to get the payload for.
    /// * `payload_hash` - The hash of the payload to get.
    ///
    /// # Returns
    ///
    /// The payload.
    pub(crate) async fn get_payload(
        &self,
        chain: u32,
        payload_hash: HashValue,
    ) -> Result<PayloadResponse, ClientError> {
        // Format the endpoint for the call
        let url = format!(
            "{}/chainweb/{CHAINWEB_API_VERSION}/mainnet01/chain/{chain}/payload/{}/outputs",
            self.chainweb_node_address,
            URL_SAFE_NO_PAD.encode(payload_hash.as_ref())
        );

        // Send the HTTP request
        let response = self
            .inner
            .get(&url)
            .header(ACCEPT, "application/json")
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
        response.json().await.map_err(|err| ClientError::Request {
            endpoint: url.clone(),
            source: Box::new(err),
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

    let query = vec![
        ("minheight", target_block - block_window),
        ("maxheight", target_block + block_window),
    ];

    // Send the HTTP request
    let response = client
        .get(&url)
        .header(ACCEPT, "application/json")
        .query(&query)
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

/// Filter the uncles from the chain headers. Sometimes it happens that
/// when fetching the block headers from the Kadena API we receive
/// a list of headers that contain uncles. This function filters the uncles
/// and returns the correct headers.
///
/// The way  the filter works is by checking the height of the headers. If the height
/// of the headers is the same, it means that the headers are uncles. In this case, the
/// method looks for the block header of the next block height and leverages
/// its parent hash value to know which block is the correct one.
///
/// # Arguments
///
/// * `headers` - The headers to filter.
/// * `expected_length` - The expected length of the headers.
///
/// # Returns
///
/// The filtered headers.
///
/// # Notes
///
/// The way this method is design assumes that the headers are already sorted by height.
/// Also, it is needed that the last block height does not have an uncle, as we need its
/// child to sort it out.
fn filter_uncles_chain_headers(
    headers: Vec<KadenaHeaderRaw>,
    expected_length: usize,
) -> Result<Vec<KadenaHeaderRaw>, ClientError> {
    // If we already have the number of expected headers, return them
    if headers.len() == expected_length {
        return Ok(headers);
    }

    let mut filtered_headers = Vec::with_capacity(expected_length);

    // Iterate over the headers we received
    let mut cursor = 0;
    while filtered_headers.len() != expected_length && cursor < headers.len() {
        // If we are on the last header, add it to the filtered headers.
        // If there was a case of uncle headers the cursor would not have
        // ended at this position.
        if cursor == headers.len() - 1 {
            filtered_headers.push(headers[cursor]);
            break;
        }

        // If the height for the current header is different from the next one
        // it means that the current header is not an uncle.
        if headers[cursor].height() != headers[cursor + 1].height() {
            filtered_headers.push(headers[cursor]);

            if cursor + 1 == headers.len() - 1 {
                filtered_headers.push(headers[cursor + 1]);
            }

            cursor += 1;

        // Case where the current height has an uncle
        } else {
            // Initialize a variable to store the correct block header hash
            let mut correct_hash: [u8; DIGEST_BYTES_LENGTH] = [0; DIGEST_BYTES_LENGTH];
            // Initialize the index for our child block to one after the uncle block
            let mut child_index = cursor + 2;

            // Iterate from the first potential index of the child block to
            // the end of the headers.
            for j in cursor + 2..headers.len() {
                // When the height of the block is  incremented by one,
                // we can assume that we have found the correct child block.
                if headers[j].decoded_height() == headers[cursor].decoded_height() + 1 {
                    correct_hash = *headers[j].parent();
                    child_index = j;
                    break;
                }
            }

            // Retrieve the correct parent block
            for header in headers
                .get(cursor..child_index)
                .expect("Should be able to extract the block with the same heights")
            {
                if header.hash() == &correct_hash {
                    filtered_headers.push(*header);
                    break;
                }
            }

            // Set cursor to the child we found
            cursor = child_index;
        }
    }

    // Final check to make sure that we have the expected number of headers
    if filtered_headers.len() != expected_length {
        return Err(ClientError::Response {
            endpoint: "get_layer_block_headers".to_string(),
            source: format!(
                "Received {} headers, tried to sanitize to {} but failed",
                headers.len(),
                expected_length
            )
            .into(),
        });
    }

    Ok(filtered_headers)
}

#[cfg(all(test, feature = "kadena"))]
mod test {
    use crate::client::chainweb::{filter_uncles_chain_headers, ChainwebClient};
    use kadena_lc_core::crypto::hash::HashValue;
    use kadena_lc_core::test_utils::random_hash;
    use kadena_lc_core::types::header::chain::KadenaHeaderRaw;
    use kadena_lc_core::types::header::layer::ChainwebLayerHeader;
    use std::cmp::Ordering;

    const LIST_LENGTH: usize = 10;
    const API_ENDPOINT: &str = "http://api.chainweb.com";
    // Chain 10 has an uncle at this height
    const UNCLE_HEIGHT: usize = 5158070;
    const BLOCK_WINDOW: usize = 3;

    /// Utility function to generate a list of chain headers with or without an uncle.
    ///
    /// The uncle  is created at the index provided.
    fn generate_header_list(uncle_index: Option<usize>) -> Vec<KadenaHeaderRaw> {
        if let Some(0) = uncle_index {
            panic!("Index 0 Cannot be an uncle, use index 1 instead")
        }

        let mut headers = vec![KadenaHeaderRaw::default(); LIST_LENGTH];

        for i in 0..LIST_LENGTH {
            let hash = random_hash();
            // Set hash
            headers[i].set_hash(hash);
            headers[i].set_height(i as u64);

            if i != LIST_LENGTH - 1 {
                if let Some(uncle_index) = uncle_index {
                    match i.cmp(&uncle_index) {
                        Ordering::Equal => {
                            let uncle_height = headers[i - 1].decoded_height();
                            let child_parent = HashValue::new(*headers[i - 1].hash());

                            headers[i].set_height(uncle_height);
                            headers[i + 1].set_parent(child_parent);

                            if i != 1 {
                                let uncle_parent = HashValue::new(*headers[i - 2].hash());
                                headers[i].set_parent(uncle_parent);
                            }

                            continue;
                        }
                        Ordering::Greater => {
                            headers[i].set_height(i as u64 - 1);
                        }
                        Ordering::Less => {}
                    }
                }
                headers[i + 1].set_parent(hash);
            }
        }

        headers
    }

    #[test]
    fn test_filter_uncles_chain_headers_no_uncles() {
        let chain_headers = generate_header_list(None);

        let filtered_list =
            filter_uncles_chain_headers(chain_headers.clone(), LIST_LENGTH).unwrap();

        assert_eq!(chain_headers, filtered_list);
    }

    #[test]
    fn test_filter_uncles_chain_headers_uncles_middle_height() {
        let mut chain_headers = generate_header_list(Some(5));

        let filtered_list =
            filter_uncles_chain_headers(chain_headers.clone(), LIST_LENGTH - 1).unwrap();

        chain_headers.remove(5);

        assert_eq!(chain_headers, filtered_list);
    }

    #[test]
    fn test_filter_uncles_chain_headers_uncles_first_height() {
        let mut chain_headers = generate_header_list(Some(1));

        let filtered_list =
            filter_uncles_chain_headers(chain_headers.clone(), LIST_LENGTH - 1).unwrap();

        chain_headers.remove(1);

        assert_eq!(chain_headers, filtered_list);
    }

    #[allow(clippy::needless_return)]
    #[tokio::test]
    async fn test_get_layer_block_headers_uncle_last_height() {
        let layer_blocks = ChainwebClient::new(API_ENDPOINT)
            .get_layer_block_headers(UNCLE_HEIGHT - BLOCK_WINDOW, BLOCK_WINDOW)
            .await
            .expect("Should be able to get layer block headers");

        ChainwebLayerHeader::verify(&layer_blocks)
            .expect("Should be able to verify layer block headers");
    }
}
