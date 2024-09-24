// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use kadena_lc::client::Client;
use kadena_lc::proofs::ProvingMode;
use kadena_lc_core::crypto::hash::HashValue;
use kadena_lc_core::types::header::layer::ChainwebLayerHeader;
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

    // Test verification for the longest chain
    let kadena_headers = client
        .get_layer_block_headers(TARGET_BLOCK, BLOCK_WINDOW)
        .await?;

    let (first_hash, target_hash, verified_confirmation_work) =
        ChainwebLayerHeader::verify(&kadena_headers)?;

    let confirmation_work = ChainwebLayerHeader::cumulative_produced_work(
        kadena_headers[kadena_headers.len() / 2..kadena_headers.len() - 1].to_vec(),
    )
    .expect("Should be able to calculate cumulative work");

    assert_eq!(confirmation_work, verified_confirmation_work,);
    assert_eq!(
        first_hash,
        kadena_headers
            .first()
            .expect("Should have a first header")
            .header_root()
            .expect("Should have a header root"),
    );
    assert_eq!(
        target_hash,
        kadena_headers[kadena_headers.len() / 2]
            .header_root()
            .expect("Should have a header root"),
    );

    let target_block = kadena_headers
        .get(kadena_headers.len() / 2)
        .unwrap()
        .clone();

    let payload = client
        .get_payload(
            0,
            HashValue::new(*target_block.chain_headers().first().unwrap().payload()),
        )
        .await
        .unwrap();

    let request_key = payload.get_transaction_output_key(0)?;

    let spv = client.get_spv(0, request_key).await?;

    spv.verify(&HashValue::new(
        *target_block
            .chain_headers()
            .first()
            .expect("Should have a header root")
            .hash(),
    ))?;

    Ok(())
}
