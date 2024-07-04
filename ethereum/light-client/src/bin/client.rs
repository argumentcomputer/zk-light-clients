// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;

pub const BEACON_NODE_ADDRESS: &str = "https://www.lightclientdata.org";
pub const CHECKPOINT_SERVICE_ADDRESS: &str = "https://sync-mainnet.beaconcha.in";

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

    info!("Bootstrap data: {:?}", bootstrap);
}
