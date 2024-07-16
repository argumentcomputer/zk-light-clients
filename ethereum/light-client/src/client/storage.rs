// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # RPC client module
//!
//! This module contains the client for the RPC Provider. It is responsible for fetching the data
//! for storage inclusion proof.
//!
//! It maintains an internal HTTP client to handle communication with the RPC Provider API.

use crate::client::error::ClientError;
use ethers_core::types::EIP1186ProofResponse;
use getset::Getters;
use reqwest::header::CONTENT_TYPE;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct GetProofResponse {
    id: u64,
    jsonrpc: String,
    result: EIP1186ProofResponse,
}

/// An internal client to handle communication with the RPC Provider.
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub(crate)")]
pub(crate) struct StorageClient {
    /// The address of the RPC provider.
    storage_provider_address: String,
    /// The inner HTTP client.
    inner: Client,
}

impl StorageClient {
    /// Create a new client with the given address.
    ///
    /// # Arguments
    ///
    /// * `rpc_provider_address` - The address of the RPC Provider.
    ///
    /// # Returns
    ///
    /// A new `BeaconClient`.
    pub(crate) fn new(rpc_provider_address: &str) -> Self {
        Self {
            storage_provider_address: rpc_provider_address.to_string(),
            inner: Client::new(),
        }
    }

    /// `get_proof` makes an HTTP request to the RPC Provider API to get the proof of inclusion
    /// for the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to get the proof for.
    ///
    /// # Returns
    ///
    /// The proof of inclusion.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub(crate) async fn get_proof(
        &self,
        address: &str,
    ) -> Result<EIP1186ProofResponse, ClientError> {
        let address = address.to_string();
        // Generate body
        let body = format!(
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getProof",
                "id": 1,
                "params": [address, [], "latest"]
            })
        );

        // Send the HTTP request
        let response = self
            .inner
            .post(&self.storage_provider_address)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|err| ClientError::Request {
                endpoint: "eth_getProof".into(),
                source: Box::new(err),
            })?;

        if !response.status().is_success() {
            return Err(ClientError::Request {
                endpoint: "eth_getProof".into(),
                source: format!(
                    "Request not successful, got HTTP code {}",
                    response.status().as_str()
                )
                .into(),
            });
        }

        // Deserialize the response
        let deserialized: GetProofResponse =
            response.json().await.map_err(|err| ClientError::Request {
                endpoint: "eth_getProof".into(),
                source: err.into(),
            })?;

        Ok(deserialized.result)
    }
}
