// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Beacon client module
//!
//! This module contains the client for the Beacon Node API. It is responsible for fetching the data
//! necessary to prove sync committee changes and value inclusion in the state of the Ethereum network.
//!
//! It maintains an internal HTTP client to handle communication with the Beacon Node.

use crate::client::error::ClientError;
use crate::types::beacon::bootstrap::Bootstrap;
use crate::types::beacon::update::UpdateResponse;
use getset::Getters;
use reqwest::header::ACCEPT;
use reqwest::Client;

/// An internal client to handle communication with a Beacon Node.
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub(crate)")]
pub(crate) struct BeaconClient {
    /// The address of the Beacon Node API.
    beacon_node_address: String,
    /// The inner HTTP client.
    inner: Client,
}

impl BeaconClient {
    /// Create a new client with the given address.
    ///
    /// # Arguments
    ///
    /// * `beacon_node_address` - The address of the Beacon Node API.
    ///
    /// # Returns
    ///
    /// A new `BeaconClient`.
    pub(crate) fn new(beacon_node_address: &str) -> Self {
        Self {
            beacon_node_address: beacon_node_address.to_string(),
            inner: Client::new(),
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
    pub(crate) async fn get_bootstrap_data(
        &self,
        checkpoint: &str,
    ) -> Result<Bootstrap, ClientError> {
        // Format the endpoint for the call
        let url = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{}",
            self.beacon_node_address, checkpoint
        );

        // Send the HTTP request
        let response = self
            .inner
            .get(&url)
            .header(ACCEPT, "application/octet-stream")
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
        let bytes = response.bytes().await.map_err(|err| ClientError::Request {
            endpoint: url.clone(),
            source: err.into(),
        })?;

        let bootstrap: Bootstrap =
            Bootstrap::from_ssz_bytes(bytes.as_ref()).map_err(|err| ClientError::Request {
                endpoint: url,
                source: err.into(),
            })?;

        Ok(bootstrap)
    }

    /// `get_update_data` makes an HTTP request to the Beacon Node API to get the update data.
    ///
    /// # Arguments
    ///
    /// * `start_period` - The start period to get the update data for.
    /// * `count` - The number of updates to get. Maximum number is set at 128, see [the specifications](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration).
    ///
    /// # Returns
    ///
    /// The update data.
    pub(crate) async fn get_update_data(
        &self,
        start_period: u64,
        count: u8,
    ) -> Result<UpdateResponse, ClientError> {
        // Format the endpoint for the call
        let url = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.beacon_node_address, start_period, count
        );

        // Send the HTTP request
        let response = self
            .inner
            .get(&url)
            .header(ACCEPT, "application/octet-stream")
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
        let bytes = response.bytes().await.map_err(|err| ClientError::Request {
            endpoint: url.clone(),
            source: err.into(),
        })?;

        let update_response: UpdateResponse = UpdateResponse::from_ssz_bytes(bytes.as_ref())
            .map_err(|err| ClientError::Request {
                endpoint: url,
                source: err.into(),
            })?;

        Ok(update_response)
    }
}
