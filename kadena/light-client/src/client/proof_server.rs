// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Proof Server client module
//!
//! This module contains the client to connect and query the Proof Server. It creates one-time TCP
//! connections to the Proof Server to generate and verify our proofs.

use crate::client::error::ClientError;
use crate::client::utils::test_connection;
use crate::proofs::longest_chain::LongestChainIn;
use crate::proofs::{ProofType, ProvingMode};
use crate::types::network::Request;
use kadena_lc_core::types::header::layer::ChainwebLayerHeader;
use reqwest::header::CONTENT_TYPE;
use reqwest::Client;

/// An internal client to handle communication with a Checkpoint Provider.
#[derive(Debug, Clone)]
pub(crate) struct ProofServerClient {
    /// The address of the Proof Server.
    address: String,
    /// The inner HTTP client.
    inner: Client,
}

impl ProofServerClient {
    /// Create a new client with the given address.
    ///
    /// # Arguments
    ///
    /// * `proof_server_address` - The address of the Proof Server.
    ///
    /// # Returns
    ///
    /// A new `ProofServerClient`.
    pub(crate) fn new(proof_server_address: &str) -> Self {
        Self {
            address: proof_server_address.to_string(),
            inner: Client::new(),
        }
    }

    /// Test the connection to the proof server.
    ///
    /// # Returns
    ///
    /// A result indicating whether the connection was successful.
    pub(crate) async fn test_endpoint(&self) -> Result<(), ClientError> {
        // Try to connect to the proof server
        test_connection(&self.address).await
    }

    /// Prove that a received list of Chainweb layer block headers is
    /// valid by invoking [`ChainwebLayerHeader::verify`].
    ///
    /// # Arguments
    ///
    /// * `proving_mode` - The proving mode to use, either STARK or SNARK.
    /// * `layer_block_headers` - The list of Chainweb layer block headers to prove.
    ///
    /// # Returns
    ///
    /// A proof of the longest chain.
    pub(crate) async fn prove_longest_chain(
        &self,
        proving_mode: ProvingMode,
        layer_block_headers: Vec<ChainwebLayerHeader>,
    ) -> Result<ProofType, ClientError> {
        let url = format!("http://{}/longest-chain/proof", self.address);

        let inputs = LongestChainIn::new(layer_block_headers);
        let request = Request::ProveLongestChain(Box::new((proving_mode, inputs)));

        let response = self
            .post_request(
                &url,
                request.to_bytes().map_err(|err| ClientError::Request {
                    endpoint: "ProofServer::ProveCommitteeChange".into(),
                    source: err.into(),
                })?,
            )
            .await?;

        ProofType::from_bytes(&response).map_err(|err| ClientError::Response {
            endpoint: "ProofServer::ProveCommitteeChange".into(),
            source: err.into(),
        })
    }

    /// Verify a proof for the longest chain.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the proof is valid.
    pub(crate) async fn verify_longest_chain(&self, proof: ProofType) -> Result<bool, ClientError> {
        let url = format!("http://{}/committee/verify", self.address);

        let request = Request::VerifyLongestChain(Box::new(proof));

        let response = self
            .post_request(
                &url,
                request.to_bytes().map_err(|err| ClientError::Request {
                    endpoint: "ProofServer::VerifyCommitteeChange".into(),
                    source: err.into(),
                })?,
            )
            .await?;

        Ok(response.first().unwrap_or(&0) == &1)
    }

    /// Send a POST request to the given URL with the given request body.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to send the request to.
    /// * `request` - The request body to send.
    ///
    /// # Returns
    ///
    /// The response from the server.
    async fn post_request(&self, url: &str, request: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        // Call the endpoint.
        let response = self
            .inner
            .post(url)
            .body(request)
            .header(CONTENT_TYPE, "application/octet-stream")
            .send()
            .await
            .map_err(|err| ClientError::Request {
                endpoint: url.into(),
                source: Box::new(err),
            })?;

        // Store the bytes in a variable first.
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| ClientError::Response {
                endpoint: url.into(),
                source: err.into(),
            })
    }
}
