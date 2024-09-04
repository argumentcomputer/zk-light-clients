// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::Parser;
use kadena_lc::client::Client;
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

    let client = Client::new(chainweb_node_address.as_str());

    let kadena_headers = client
        .get_layer_block_headers(TARGET_BLOCK, BLOCK_WINDOW)
        .await?;

    for layer_header in kadena_headers.iter() {
        info!("Block height {}", layer_header.height());
        for chain_header in layer_header.chain_headers() {
            info!("{}", URL_SAFE_NO_PAD.encode(chain_header.hash()));
        }
    }

    Ok(())
}
