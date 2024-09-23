// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use kadena_lc::client::Client;
use kadena_lc::proofs::ProvingMode;
use kadena_lc_core::crypto::hash::HashValue;
use std::env;
use std::sync::Arc;

pub const TARGET_BLOCK: usize = 5099345;
pub const BLOCK_WINDOW: usize = 3;

/// The CLI for the light client.
#[derive(Parser)]
struct Cli {
    /// The address of the chainweb node API.
    #[arg(short, long)]
    chainweb_node_address: String,

    /// The address of the proof server
    #[arg(short, long)]
    proof_server_address: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Get proving mode for the light client.
    let mode_str: String = env::var("MODE").unwrap_or_else(|_| "STARK".into());
    let _mode = ProvingMode::try_from(mode_str.as_str()).expect("MODE should be STARK or SNARK");

    // Extract all addresses from the command.
    let Cli {
        chainweb_node_address,
        proof_server_address,
        ..
    } = Cli::parse();

    // Initialize the logger.
    env_logger::init();

    let proof_server_address = Arc::new(proof_server_address);
    let chainweb_node_address = Arc::new(chainweb_node_address);

    let client = Client::new(
        chainweb_node_address.as_str(),
        proof_server_address.as_str(),
    );

    let kadena_headers = client
        .get_layer_block_headers(TARGET_BLOCK, BLOCK_WINDOW)
        .await?;

    let target_block = kadena_headers
        .get(kadena_headers.len() / 2)
        .unwrap()
        .clone();
    // Fetch SPV proof for the target block height of chain 0
    // Fetching SPV for request key "Xe7GN8pA4paS-vF0L4EOTkcBj_K4u72D6xdKg7E724M"
    // https://explorer.chainweb.com/mainnet/txdetail/Xe7GN8pA4paS-vF0L4EOTkcBj_K4u72D6xdKg7E724M
    let spv = client
        .get_spv(
            0,
            String::from("Xe7GN8pA4paS-vF0L4EOTkcBj_K4u72D6xdKg7E724M"),
        )
        .await
        .unwrap();

    println!("{:?}", spv.subject().input().as_bytes().len());

    println!("BlockHeader Hash");
    println!(
        "{}",
        spv.verify(&HashValue::new(
            *target_block.chain_headers().first().unwrap().hash()
        ))
        .unwrap()
    );

    Ok(())
}
