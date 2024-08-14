// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Checkpoint client module
//!
//! This module contains the client for the Checkpoint Provider. It is responsible for fetching the data
//! for the latest finalized block root.
//!
//! It maintains an internal HTTP client to handle communication with the Checkpoint Provider API.

use crate::client::error::ClientError;
use crate::types::checkpoint::{Checkpoint, SlotsResponse};
use reqwest::header::ACCEPT;
use reqwest::Client;
use std::time::Duration;

/// An internal client to handle communication with a Checkpoint Provider.
#[derive(Debug, Clone)]
pub(crate) struct CheckpointClient {
    /// The address of the Checkpoint Provider API.
    address: String,
    /// The inner HTTP client.
    inner: Client,
}

impl CheckpointClient {
    pub(crate) fn new(checkpoint_provider_address: &str) -> Self {
        Self {
            address: checkpoint_provider_address.to_string(),
            inner: Client::new(),
        }
    }

    /// Test the connection to the checkpoint provider.
    ///
    /// # Returns
    ///
    /// A result indicating whether the connection was successful.
    pub(crate) async fn test_endpoint(&self) -> Result<(), ClientError> {
        // Try to connect to the proof server
        let mut retries = 0;
        loop {
            match self.inner.get(&self.address).send().await {
                Ok(_) => {
                    break;
                }
                Err(_) if retries < 10 => {
                    retries += 1;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(_) => {
                    return Err(ClientError::Connection {
                        address: self.address.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// `get_checkpoint` makes an HTTP request to the Checkpoint Provider API to get the checkpoint
    /// at the specified slot. If no particular slot is specified, returns the latest checkpoint.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot to get the checkpoint for. If `None`, returns the latest checkpoint.
    ///
    /// # Returns
    ///
    /// The checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub(crate) async fn get_checkpoint(
        &self,
        slot: Option<u64>,
    ) -> Result<Checkpoint, ClientError> {
        // Format endpoint for the call.
        let url = format!("{}/checkpointz/v1/beacon/slots", self.address);

        // Call the endpoint.
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

        // Deserialize response.
        let response: SlotsResponse =
            response.json().await.map_err(|err| ClientError::Request {
                endpoint: url.clone(),
                source: Box::new(err),
            })?;

        // If no slot specified, returns the latest valid checkpoint. Otherwise, return the checkpoint
        // for the specified slot.
        if slot.is_none() {
            Ok(response
                .data()
                .slots()
                .iter()
                .find(|checkpoint| checkpoint.block_root().is_some())
                .ok_or_else(|| ClientError::Response {
                    endpoint: url,
                    source: "No slots found in response".into(),
                })?
                .clone())
        } else {
            let slot = slot.unwrap();
            Ok(response
                .data()
                .slots()
                .iter()
                .filter(|checkpoint| checkpoint.block_root().is_some())
                .find(|checkpoint| checkpoint.slot() == &format!("{slot}"))
                .ok_or_else(|| ClientError::Response {
                    endpoint: url,
                    source: format!("No slot {} found in response", slot).into(),
                })?
                .clone())
        }
    }
}
