// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Client module
//!
//! This module contains the client for the light client. It is the entrypoint for any needed remote call.
//! The client is composed of two main components: the Beacon Client and the Checkpoint Client.
//!
//! ## Sub-modules
//!
//! - `beacon`: The Beacon Client is responsible for fetching the data necessary to prove sync committee changes
//!   and value inclusion in the state of the Ethereum network.
//! - `checkpoint`: The Checkpoint Client is responsible for fetching the data of the latest finalized block root.

use crate::client::beacon::BeaconClient;
use crate::client::checkpoint::CheckpointClient;
use crate::client::error::ClientError;
use crate::client::proof_server::ProofServerClient;
use crate::client::storage::StorageClient;
use crate::proofs::{ProofType, ProvingMode};
use crate::types::beacon::update::UpdateResponse;
use crate::types::checkpoint::Checkpoint;
use ethereum_lc_core::merkle::storage_proofs::EIP1186Proof;
use ethereum_lc_core::types::bootstrap::Bootstrap;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::{FinalityUpdate, Update};
use ethers_core::types::EIP1186ProofResponse;

pub(crate) mod beacon;
pub(crate) mod checkpoint;
pub mod error;
pub(crate) mod proof_server;
pub mod storage;

/// The client for the light client. It is the entrypoint for any needed remote call.
#[derive(Debug, Clone)]
pub struct Client {
    beacon_client: BeaconClient,
    checkpoint_client: CheckpointClient,
    proof_server_client: ProofServerClient,
    storage_client: StorageClient,
}

impl Client {
    /// Create a new client with the given addresses.
    ///
    /// # Arguments
    ///
    /// * `checkpoint_provider_address` - The address of the Checkpoint Provider API.
    /// * `beacon_node_address` - The address of the Beacon Node API.
    /// * `proof_server_address` - The address of the Proof Server API.
    /// * `storage_provider_address` - The address of the RPC Provider API.
    ///
    /// # Returns
    ///
    /// A new `Client`.
    pub fn new(
        checkpoint_provider_address: &str,
        beacon_node_address: &str,
        proof_server_address: &str,
        storage_provider_address: &str,
    ) -> Self {
        Self {
            beacon_client: BeaconClient::new(beacon_node_address),
            checkpoint_client: CheckpointClient::new(checkpoint_provider_address),
            proof_server_client: ProofServerClient::new(proof_server_address),
            storage_client: StorageClient::new(storage_provider_address),
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
    pub async fn get_bootstrap_data(&self, checkpoint: &str) -> Result<Bootstrap, ClientError> {
        self.beacon_client.get_bootstrap_data(checkpoint).await
    }

    /// `get_checkpoint` makes an HTTP request to the Checkpoint Provider API to get the checkpoint
    /// at the specified slot. If no particular slot is specified, returns the latest checkpoint.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot to get the checkpoint for.
    ///
    /// # Returns
    ///
    /// The fetched checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn get_checkpoint(&self, slot: Option<u64>) -> Result<Checkpoint, ClientError> {
        self.checkpoint_client.get_checkpoint(slot).await
    }

    /// `get_update_data` makes an HTTP request to the Beacon Node API to get the update data.
    ///
    /// # Arguments
    ///
    /// * `sync_period` - The sync committee period.
    /// * `max` - The maximum number of updates to fetch. Maxed at 128.
    ///
    /// # Returns
    ///
    /// The update data.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn get_update_data(
        &self,
        sync_period: u64,
        max: u8,
    ) -> Result<UpdateResponse, ClientError> {
        self.beacon_client.get_update_data(sync_period, max).await
    }

    /// `get_finality_update` makes an HTTP request to the Beacon Node API to get the finality update.
    ///
    /// # Returns
    ///
    /// The finality update.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn get_finality_update(&self) -> Result<FinalityUpdate, ClientError> {
        self.beacon_client.get_finality_update().await
    }

    /// `prove_committee_change` makes a request to the Proof Server API to generate the proof of a committee change.
    ///
    /// # Arguments
    ///
    /// * `proving_mode` - The proving mode, either STARK or SNARK.
    /// * `store` - The light client store.
    /// * `update` - The update data.
    ///
    /// # Returns
    ///
    /// The proof of the committee change.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn prove_committee_change(
        &self,
        proving_mode: ProvingMode,
        store: LightClientStore,
        update: Update,
    ) -> Result<ProofType, ClientError> {
        Box::pin(
            self.proof_server_client
                .prove_committee_change(proving_mode, store, update),
        )
        .await
    }

    /// `verify_committee_change` makes a request to the Proof Server API to verify the proof of a committee change.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof of the committee change.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the proof is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn verify_committee_change(&self, proof: ProofType) -> Result<bool, ClientError> {
        self.proof_server_client
            .verify_committee_change(proof)
            .await
    }

    /// `get_proof` makes an HTTP request to the RPC Provider API to get the proof of a storage inclusion.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to get the proof for.
    /// * `storage_keys` - The storage keys to get the proof for.
    /// * `block_hash` - The block hash to get the proof for.
    ///
    /// # Returns
    ///
    /// The proof of the storage inclusion.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn get_proof(
        &self,
        address: &str,
        storage_keys: &[String],
        block_hash: &str,
    ) -> Result<EIP1186ProofResponse, ClientError> {
        self.storage_client
            .get_proof(address, storage_keys, block_hash)
            .await
    }

    /// `prove_storage_inclusion` makes a request to the Proof Server API to generate the proof of a storage inclusion.
    ///
    /// # Arguments
    ///
    /// * `proving_mode` - The proving mode, either STARK or SNARK.
    /// * `store` - The light client store.
    /// * `update` - The update data.
    /// * `eip1186_proof` - The EIP1186 proof.
    ///
    /// # Returns
    ///
    /// The proof of the storage inclusion.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn prove_storage_inclusion(
        &self,
        proving_mode: ProvingMode,
        store: LightClientStore,
        update: Update,
        eip1186_proof: EIP1186Proof,
    ) -> Result<ProofType, ClientError> {
        Box::pin(self.proof_server_client.prove_storage_inclusion(
            proving_mode,
            store,
            update,
            eip1186_proof,
        ))
        .await
    }

    /// `verify_storage_inclusion` makes a request to the Proof Server API to verify the proof of a storage inclusion.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof of the storage inclusion.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the proof is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not successful or properly formatted.
    pub async fn verify_storage_inclusion(&self, proof: ProofType) -> Result<bool, ClientError> {
        self.proof_server_client
            .verify_storage_inclusion(proof)
            .await
    }
}
