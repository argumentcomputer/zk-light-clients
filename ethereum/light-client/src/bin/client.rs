// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use ethereum_lc::client::utils::calc_sync_period;
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

    let sync_period = calc_sync_period(bootstrap.header().beacon().slot());

    let update = client
        .get_update_data(sync_period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .expect("Failed to fetch update data");

    println!("Update: {:?}", update);

    // TODO verify the updates against the bootstrap checkpoint
}
