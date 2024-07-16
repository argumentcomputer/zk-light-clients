// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use ethereum_lc::client::Client;
use ethereum_lc::proofs::ProvingMode;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::utils::calc_sync_period;
use log::info;
use std::sync::Arc;

/// The maximum number of light client updates that can be requested.
///
/// From [the Altair specifications](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration).
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u8 = 128;

/// Address for which we fetch proof of inclusion
pub const ADDRESS: &str = "0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97";

/// The CLI for the light client.
#[derive(Parser)]
struct Cli {
    /// The address of the checkpoint service provider.
    ///
    /// See https://eth-clients.github.io/checkpoint-sync-endpoints
    #[arg(short, long)]
    checkpoint_provider_address: String,

    /// The address for the beacon node API.
    ///
    /// It is recommended to use https://www.lightclientdata.org
    #[arg(short, long)]
    beacon_node_address: String,

    /// The address of the proof server
    #[arg(short, long)]
    proof_server_address: String,

    /// The address of the RPC provider
    #[arg(short, long)]
    rpc_provider_address: String,
}

pub struct ClientState {
    client: Client,
    store: LightClientStore,
}

#[tokio::main]
async fn main() {
    let Cli {
        checkpoint_provider_address,
        beacon_node_address,
        proof_server_address,
        rpc_provider_address,
        ..
    } = Cli::parse();

    // Initialize the logger.
    env_logger::init();

    let checkpoint_provider_address = Arc::new(checkpoint_provider_address);
    let beacon_node_address = Arc::new(beacon_node_address);
    let proof_server_address = Arc::new(proof_server_address);
    let rpc_provider_address = Arc::new(rpc_provider_address);

    let state = initialize_light_client(
        checkpoint_provider_address,
        beacon_node_address,
        proof_server_address,
        rpc_provider_address,
    )
    .await
    .expect("Failed to initialize light client");

    info!("Light client initialized successfully");

    info!("Fetching proof of storage inclusion for the latest block...");

    let inclusion_merkle_proof = state
        .client
        .get_proof(ADDRESS, &[])
        .await
        .expect("Failed to fetch storage inclusion proof");

    println!("Proof of storage inclusion: {:?}", inclusion_merkle_proof);
}

async fn initialize_light_client(
    checkpoint_provider_address: Arc<String>,
    beacon_node_address: Arc<String>,
    proof_server_address: Arc<String>,
    rpc_provider_address: Arc<String>,
) -> Result<ClientState> {
    // Instantiate client.
    let client = Client::new(
        &checkpoint_provider_address,
        &beacon_node_address,
        &proof_server_address,
        &rpc_provider_address,
    );

    info!("Fetching latest state checkpoint and bootstrap data...");

    // Fetch latest state checkpoint.
    let checkpoint = client
        .get_checkpoint(None)
        .await
        .expect("Failed to fetch checkpoint");

    let checkpoint_block_root = match checkpoint.block_root() {
        Some(block_root) => block_root,
        None => panic!("No block root found in checkpoint"),
    };

    info!("Latest checkpoint: {:?}", checkpoint_block_root);

    // Fetch bootstrap data.
    let bootstrap = client
        .get_bootstrap_data(checkpoint_block_root)
        .await
        .expect("Failed to fetch bootstrap data");

    info!(
        "Initializing Light Client store at checkpoint: {:?}",
        checkpoint_block_root
    );

    // Initialize store
    let trusted_block_root = hex::decode(
        checkpoint_block_root
            .strip_prefix("0x")
            .expect("Checkpoint should start with \"0x\""),
    )
    .expect("Failed to decode checkpoint block root")
    .try_into()
    .expect("Failed to convert checkpoint bytes to Bytes32");

    let store = LightClientStore::initialize(trusted_block_root, &bootstrap)
        .expect("Could not initialize the store based on bootstrap data");

    let mut client_state = ClientState { client, store };

    info!("Fetching updates...");

    // Fetch updates
    let sync_period = calc_sync_period(bootstrap.header().beacon().slot());

    let update_response = client_state
        .client
        .get_update_data(sync_period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .expect("Failed to fetch update data");

    info!(
        "Got {} updates, starting processing...",
        update_response.updates().len()
    );

    for update in update_response.updates() {
        info!(
            "Processing update at slot: {:?}",
            update.update().attested_header().beacon().slot()
        );

        if calc_sync_period(bootstrap.header().beacon().slot())
            != calc_sync_period(update.update().attested_header().beacon().slot())
        {
            info!("Sync period changed, updating store...");
        }

        let proof = client_state
            .client
            .prove_committee_change(ProvingMode::STARK, &client_state.store, update.update())
            .await
            .expect("Failed to prove committee change");

        client_state
            .client
            .verify_committee_change(proof.clone())
            .await
            .expect("Failed to prove committee change");

        // TODO this is redundant, to simplify
        client_state
            .store
            .process_light_client_update(update.update())
            .unwrap()
    }

    Ok(client_state)
}
