// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use ethereum_lc_core::merkle::Merkleized;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::utils::calc_sync_period;
use log::info;

/// The maximum number of light client updates that can be requested.
///
/// From [the Altair specifications](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration).
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u8 = 128;

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
}

#[tokio::main]
async fn main() {
    let Cli {
        checkpoint_provider_address,
        beacon_node_address,
        ..
    } = Cli::parse();

    // Initialize the logger.
    env_logger::init();

    // Instantiate client.
    let client =
        ethereum_lc::client::Client::new(&checkpoint_provider_address, &beacon_node_address);

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

    let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap)
        .expect("Could not initialize the store based on bootstrap data");

    info!("Fetching updates...");

    // Fetch updates
    let sync_period = calc_sync_period(bootstrap.header().beacon().slot());

    let update_response = client
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

        store
            .process_light_client_update(update.update())
            .expect("Failed to process update");

        assert_eq!(
            store
                .next_sync_committee()
                .clone()
                .unwrap()
                .hash_tree_root()
                .unwrap(),
            update
                .update()
                .next_sync_committee()
                .hash_tree_root()
                .unwrap()
        );

        if calc_sync_period(bootstrap.header().beacon().slot())
            != calc_sync_period(update.update().attested_header().beacon().slot())
        {
            assert_eq!(
                store.finalized_header().hash_tree_root().unwrap(),
                update.update().finalized_header().hash_tree_root().unwrap()
            );
            assert_eq!(
                store.optimistic_header().hash_tree_root().unwrap(),
                update.update().finalized_header().hash_tree_root().unwrap()
            )
        }
    }
}
