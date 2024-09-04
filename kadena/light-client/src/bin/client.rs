// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::Parser;
use kadena_lc::client::Client;
use kadena_lc_core::crypto::U256;
use log::info;
use std::sync::Arc;

pub const TARGET_BLOCK: usize = 5099345;
pub const BLOCK_WINDOW: usize = 3;

/// The CLI for the light client.
#[derive(Parser)]
struct Cli {
    /// The address of the chainweb node API.
    #[arg(short, long)]
    chainweb_node_address: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Extract all addresses from the command.
    let Cli {
        chainweb_node_address,
        ..
    } = Cli::parse();

    // Initialize the logger.
    env_logger::init();

    let chainweb_node_address = Arc::new(chainweb_node_address);

    let target = U256::from_little_endian(
        &hex::decode(b"f3dc1433cc12fa947b0c77dac17132247deddee21fbdd7951000000000000000").unwrap(),
    );
    println!("target: {target}",);
    let hash = U256::from_little_endian(
        &hex::decode(b"4913622f5bb0b66de8bc3074ab7809915d459af7770d95570498a339c7e1b2f1").unwrap(),
    );
    println!("hash: {hash}",);
    println!("{}", hash <= target);

    let weight = U256::from_little_endian(
        &hex::decode(b"bb243efdfa04d4459a6901000000000000000000000000000000000000000000").unwrap(),
    );
    println!("weight: {weight}",);
    println!("{}", weight <= target);

    let pow_hash = U256::from_big_endian(
        &hex::decode(b"000000000000000d9817efc021255bb06e1fc96c3c257b1b4d4340e37e811b89").unwrap(),
    );
    println!("pow hash: {pow_hash}",);
    println!("{}", pow_hash <= target);

    let client = Client::new(chainweb_node_address.as_str());

    let kadena_headers = client
        .get_layer_block_headers(TARGET_BLOCK, BLOCK_WINDOW)
        .await?;

    for layer_header in kadena_headers.iter() {
        info!("Block height {}", layer_header.height());
        info!(
            "Block difficulty: {}",
            U256::from_little_endian(layer_header.chain_headers().first().unwrap().target())
                .to_string()
        );
        for chain_header in layer_header.chain_headers() {
            info!(
                "     Chain ID {}",
                u32::from_le_bytes(*chain_header.chain())
            );
            info!(
                "     Block hash {}",
                URL_SAFE_NO_PAD.encode(chain_header.hash())
            );

            let target = U256::from_little_endian(chain_header.target());
            println!("target: {target}",);
            let hash = U256::from_little_endian(chain_header.hash());
            println!("hash: {hash}",);
            println!("{}", hash <= target);

            let weight = U256::from_little_endian(chain_header.weight());
            println!("weight: {weight}",);
            println!("{}", weight <= target);
            /*
            let assumed_pow_hash =
                hex::decode(b"00000000000000039633411e726c4e458f380cb662430ef4bca0f676060985c6")
                    .unwrap();
            dbg!(assumed_pow_hash);

            let calculated_pow_hash = chain_header.pow_hash()?;
            dbg!(calculated_pow_hash);*/
        }
    }

    Ok(())
}
