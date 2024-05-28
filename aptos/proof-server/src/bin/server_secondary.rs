// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use anyhow::{Error, Result};
use aptos_lc::epoch_change;
use clap::Parser;
use log::info;
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpListener};
use wp1_sdk::ProverClient;

use proof_server::{read_bytes, write_bytes, EpochChangeData, SecondaryRequest};

/// Server capable of handling proof generation and verification regarding epoch
/// changes. Such requests are expected to come from the primary server.
///
/// Making requests to this server and handling responses from it follows the
/// same logic from the primary server:
///
/// * Request data must be preceded by its size in bytes
/// * Proof responses will follow the same logic
/// * Verification responses are single bytes
///     - 0 means that the proof didn't verify
///     - 1 means that the proof did verify
///
/// The request bytes must be deserializable into `proof_server::SecondaryRequest`
/// by the `bcs` crate, so it's recommended to simply use that (pub) type when
/// producing request data.
#[derive(Parser)]
struct Cli {
    /// Address of this server. E.g. 127.0.0.1:4321
    #[arg(short, long)]
    addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { addr } = Cli::parse();

    env_logger::init();

    let listener = TcpListener::bind(addr).await?;

    info!("Server is running on {}", listener.local_addr()?);

    let prover_client = Arc::new(ProverClient::default());
    let (pk, vk) = epoch_change::generate_keys(&prover_client);
    let (pk, vk) = (Arc::new(pk), Arc::new(vk));

    loop {
        let (mut socket, _) = listener.accept().await?;
        info!("Received a connection");

        // cheap `Arc` clones
        let prover_client = prover_client.clone();
        let pk = pk.clone();
        let vk = vk.clone();

        tokio::spawn(async move {
            info!("Awaiting request data");
            let request_bytes = read_bytes(&mut socket).await?;
            info!("Request data received");

            info!("Deserializing request data");
            match bcs::from_bytes::<SecondaryRequest>(&request_bytes)? {
                SecondaryRequest::Prove(EpochChangeData {
                    trusted_state,
                    epoch_change_proof,
                }) => {
                    let stdin = epoch_change::generate_stdin(&trusted_state, &epoch_change_proof);
                    info!("Start proving");
                    let proof_handle =
                        tokio::task::spawn_blocking(move || prover_client.prove(&pk, stdin));
                    let proof = proof_handle.await??;
                    info!("Proof generated. Serializing");
                    let proof_bytes = bcs::to_bytes(&proof)?;
                    info!("Sending proof to the primary server");
                    write_bytes(&mut socket, &proof_bytes).await?;
                    info!("Proof sent");
                }
                SecondaryRequest::Verify(proof) => {
                    socket
                        .write_u8(u8::from(prover_client.verify(&proof, &vk).is_ok()))
                        .await?;
                }
            }
            Ok::<(), Error>(())
        });
    }
}
