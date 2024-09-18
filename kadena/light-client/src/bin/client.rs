// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use clap::Parser;
use kadena_lc::client::Client;
use kadena_lc::proofs::ProvingMode;
use kadena_lc::types::chainweb::SpvResponse;
use kadena_lc_core::crypto::hash::sha512::{hash_data, hash_inner, hash_tagged_data};
use kadena_lc_core::crypto::hash::HashValue;
use kadena_lc_core::merkle::spv::Spv;
use kadena_lc_core::merkle::TRANSACTION_TAG;
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
    let mode = ProvingMode::try_from(mode_str.as_str()).expect("MODE should be STARK or SNARK");

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

    // Fetch payload information for the target height of chain 0
    let outputs = client
        .get_block_payload(
            0,
            *target_block.height(),
            HashValue::new(*target_block.chain_headers().get(0).unwrap().payload()),
        )
        .await?;

    // Fetch SPV proof for the target block height of chain 0
    // Fetching SPV for request key "Xe7GN8pA4paS-vF0L4EOTkcBj_K4u72D6xdKg7E724M"
    // https://explorer.chainweb.com/mainnet/txdetail/Xe7GN8pA4paS-vF0L4EOTkcBj_K4u72D6xdKg7E724M
    let base64_spv_response = client
        .get_spv(
            0,
            String::from("Xe7GN8pA4paS-vF0L4EOTkcBj_K4u72D6xdKg7E724M"),
        )
        .await
        .unwrap();
    let decoded_spv_response = URL_SAFE_NO_PAD
        .decode(base64_spv_response.as_bytes())
        .unwrap();
    let spv_response: SpvResponse = serde_json::from_slice(&decoded_spv_response).unwrap();

    // Convert to our own SPV deserialized structure
    let spv: Spv = spv_response.try_into().unwrap();

    // Verify the SPV proof against multiple hashes
    println!("Transaction Hash");
    println!(
        "   {}",
        spv.verify(
            &HashValue::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(outputs.transactions_hash().as_bytes())
                    .unwrap()
            )
            .unwrap()
        )
        .unwrap()
    );
    println!("Outputs Hash");
    println!(
        "{}",
        spv.verify(
            &HashValue::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(outputs.outputs_hash().as_bytes())
                    .unwrap()
            )
            .unwrap()
        )
        .unwrap()
    );
    println!("Payload Hash");
    println!(
        "{}",
        spv.verify(
            &HashValue::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(outputs.payload_hash().as_bytes())
                    .unwrap()
            )
            .unwrap()
        )
        .unwrap()
    );
    println!("BlockHeader Hash");
    println!(
        "{}",
        spv.verify(&HashValue::new(
            *target_block.chain_headers().get(0).unwrap().hash()
        ))
        .unwrap()
    );

    /*let kadena_headers = client
        .get_layer_block_headers(TARGET_BLOCK, BLOCK_WINDOW)
        .await?;

    let proof = client.prove_longest_chain(mode, kadena_headers).await?;

    let valid = client.verify_longest_chain(proof).await?;

    assert!(valid);*/

    Ok(())
}
