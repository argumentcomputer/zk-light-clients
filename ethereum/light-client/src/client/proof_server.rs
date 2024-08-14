// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Proof Server client module
//!
//! This module contains the client to connect and query the Proof Server. It creates one-time TCP
//! connections to the Proof Server to generate and verify our proofs.

use crate::client::error::ClientError;
use crate::proofs::committee_change::CommitteeChangeIn;
use crate::proofs::inclusion::StorageInclusionIn;
use crate::proofs::{ProofType, ProvingMode};
use crate::types::network::Request;
use crate::utils::{read_bytes, write_bytes};
use ethereum_lc_core::merkle::storage_proofs::EIP1186Proof;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::Update;
use std::time::Duration;
use tokio::net::TcpStream;

/// An internal client to handle communication with a Checkpoint Provider.
#[derive(Debug, Clone)]
pub(crate) struct ProofServerClient {
    /// The address of the Proof Server.
    address: String,
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
        }
    }

    /// Test the connection to the proof server.
    ///
    /// # Returns
    ///
    /// A result indicating whether the connection was successful.
    pub(crate) async fn test_endpoint(&self) -> Result<(), ClientError> {
        // Try to connect to the proof server
        let mut retries = 0;
        loop {
            match TcpStream::connect(&self.address).await {
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

    /// Prove a sync committee change by executing the [`LightClientStore::process_light_client_update`]
    /// and proving its correct execution.
    ///
    /// # Arguments
    ///
    /// * `proving_mode` - The proving mode to use, either STARK or SNARK.
    /// * `store` - The light client store.
    /// * `update` - The update to process.
    ///
    /// # Returns
    ///
    /// A proof of the sync committee change.
    pub(crate) async fn prove_committee_change(
        &self,
        proving_mode: ProvingMode,
        store: LightClientStore,
        update: Update,
    ) -> Result<ProofType, ClientError> {
        let mut stream =
            TcpStream::connect(&self.address)
                .await
                .map_err(|err| ClientError::Request {
                    endpoint: "ProofServer::ProveCommitteeChange".into(),
                    source: err.into(),
                })?;
        let inputs = CommitteeChangeIn::new(store, update);
        let request = Request::ProveCommitteeChange(Box::new((proving_mode, inputs)));

        write_bytes(
            &mut stream,
            &request.to_bytes().map_err(|err| ClientError::Request {
                endpoint: "ProofServer::ProveCommitteeChange".into(),
                source: err.into(),
            })?,
        )
        .await
        .map_err(|err| ClientError::Request {
            endpoint: "prover".into(),
            source: err.into(),
        })?;

        let res = read_bytes(&mut stream)
            .await
            .map_err(|err| ClientError::Response {
                endpoint: "ProofServer::ProveCommitteeChange".into(),
                source: err.into(),
            })?;

        ProofType::from_bytes(&res).map_err(|err| ClientError::Response {
            endpoint: "ProofServer::ProveCommitteeChange".into(),
            source: err.into(),
        })
    }

    /// Verify a proof of a sync committee change.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the proof is valid.
    pub(crate) async fn verify_committee_change(
        &self,
        proof: ProofType,
    ) -> Result<bool, ClientError> {
        let mut stream =
            TcpStream::connect(&self.address)
                .await
                .map_err(|err| ClientError::Request {
                    endpoint: "ProofServer::VerifyCommitteeChange".into(),
                    source: err.into(),
                })?;

        let request = Request::VerifyCommitteeChange(proof);

        write_bytes(
            &mut stream,
            &request.to_bytes().map_err(|err| ClientError::Request {
                endpoint: "ProofServer::VerifyCommitteeChange".into(),
                source: err.into(),
            })?,
        )
        .await
        .map_err(|err| ClientError::Request {
            endpoint: "prover".into(),
            source: err.into(),
        })?;

        let res = read_bytes(&mut stream)
            .await
            .map_err(|err| ClientError::Response {
                endpoint: "ProofServer::VerifyCommitteeChange".into(),
                source: err.into(),
            })?;

        if res.len() != 1 {
            return Err(ClientError::Response {
                endpoint: "ProofServer::VerifyCommitteeChange".into(),
                source: "Invalid response length".into(),
            });
        }

        Ok(res[0] == 1)
    }

    /// Prove the inclusion of a given value in the chain storage by executing [`EIP1186Proof::verify`]
    /// and proving its correct execution.
    ///
    /// # Arguments
    ///
    /// * `proving_mode` - The proving mode to use, either STARK or SNARK.
    /// * `store` - The light client store.
    /// * `update` - The update to process.
    /// * `eip1186_proof` - The EIP1186 proof to verify.
    ///
    /// # Returns
    ///
    /// A proof of the storage inclusion.
    pub(crate) async fn prove_storage_inclusion(
        &self,
        proving_mode: ProvingMode,
        store: LightClientStore,
        update: Update,
        eip1186_proof: EIP1186Proof,
    ) -> Result<ProofType, ClientError> {
        let mut stream =
            TcpStream::connect(&self.address)
                .await
                .map_err(|err| ClientError::Request {
                    endpoint: "ProofServer::ProveInclusion".into(),
                    source: err.into(),
                })?;
        let inputs = StorageInclusionIn::new(store, update, eip1186_proof);
        let request = Request::ProveInclusion(Box::new((proving_mode, inputs)));

        write_bytes(
            &mut stream,
            &request.to_bytes().map_err(|err| ClientError::Request {
                endpoint: "ProofServer::ProveInclusion".into(),
                source: err.into(),
            })?,
        )
        .await
        .map_err(|err| ClientError::Request {
            endpoint: "prover".into(),
            source: err.into(),
        })?;

        let res = read_bytes(&mut stream)
            .await
            .map_err(|err| ClientError::Response {
                endpoint: "ProofServer::ProveInclusion".into(),
                source: err.into(),
            })?;

        ProofType::from_bytes(&res).map_err(|err| ClientError::Response {
            endpoint: "ProofServer::ProveInclusion".into(),
            source: err.into(),
        })
    }

    /// Verify a proof for storage inclusion.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the proof is valid.
    pub(crate) async fn verify_storage_inclusion(
        &self,
        proof: ProofType,
    ) -> Result<bool, ClientError> {
        let mut stream =
            TcpStream::connect(&self.address)
                .await
                .map_err(|err| ClientError::Request {
                    endpoint: "ProofServer::VerifyInclusiona".into(),
                    source: err.into(),
                })?;

        let request = Request::VerifyInclusion(proof);

        write_bytes(
            &mut stream,
            &request.to_bytes().map_err(|err| ClientError::Request {
                endpoint: "ProofServer::VerifyInclusiona".into(),
                source: err.into(),
            })?,
        )
        .await
        .map_err(|err| ClientError::Request {
            endpoint: "prover".into(),
            source: err.into(),
        })?;

        let res = read_bytes(&mut stream)
            .await
            .map_err(|err| ClientError::Response {
                endpoint: "ProofServer::VerifyInclusiona".into(),
                source: err.into(),
            })?;

        if res.len() != 1 {
            return Err(ClientError::Response {
                endpoint: "ProofServer::VerifyInclusiona".into(),
                source: "Invalid response length".into(),
            });
        }

        Ok(res[0] == 1)
    }
}
