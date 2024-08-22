// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use clap::{Parser, ValueEnum};
use ethereum_lc::proofs::committee_change::CommitteeChangeProver;
use ethereum_lc::proofs::inclusion::StorageInclusionProver;
use ethereum_lc::proofs::Prover;
use ethereum_lc::types::network::Request;
use ethereum_lc::utils::{read_bytes, write_bytes};
use log::{error, info};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::spawn_blocking;

#[derive(ValueEnum, Clone, Debug, Eq, PartialEq)]
enum Mode {
    Single,
    Split,
}

#[derive(Parser)]
struct Cli {
    /// Address of this server. E.g. 127.0.0.1:1234
    #[arg(short, long)]
    addr: String,

    /// Required in 'split' mode, address of the secondary server. E.g. 127.0.0.1:4321
    #[arg(short, long)]
    snd_addr: Option<String>,

    /// Mode of operation: either 'single' or 'split'
    #[arg(short, long)]
    mode: Mode,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        addr,
        snd_addr,
        mode,
    } = Cli::parse();

    if mode == Mode::Split && snd_addr.is_none() {
        return Err(Error::msg(
            "Secondary server address is required in split mode",
        ));
    }

    env_logger::init();

    let listener = TcpListener::bind(addr).await?;
    info!("Server is running on {}", listener.local_addr()?);

    let snd_addr = Arc::new(snd_addr.unwrap_or(String::new()));
    let committee_prover = Arc::new(CommitteeChangeProver::new());
    let inclusion_prover = Arc::new(StorageInclusionProver::new());

    loop {
        let (mut client_stream, _) = listener.accept().await?;
        info!("Received a connection");

        let committee_prover = committee_prover.clone();
        let inclusion_prover = inclusion_prover.clone();

        let snd_addr = snd_addr.clone();
        let mode = mode.clone();

        tokio::spawn(async move {
            info!("Awaiting request");
            let request_bytes = read_bytes(&mut client_stream).await?;
            info!("Request received");

            info!("Deserializing request");
            match Request::from_bytes(&request_bytes) {
                Ok(request) => match request {
                    Request::ProveInclusion(boxed) => {
                        info!("Start proving");
                        let proof_handle = spawn_blocking(move || {
                            let (proving_mode, inputs) = *boxed;
                            inclusion_prover.prove(inputs, proving_mode)
                        });
                        let proof = proof_handle.await??;
                        info!("Proof generated. Serializing");
                        let proof_bytes = proof.to_bytes()?;
                        info!("Sending proof");
                        write_bytes(&mut client_stream, &proof_bytes).await?;
                        info!("Proof sent");
                    }
                    Request::VerifyInclusion(proof) => {
                        write_bytes(
                            &mut client_stream,
                            &[u8::from(inclusion_prover.verify(&proof).is_ok())],
                        )
                        .await?;
                    }
                    Request::ProveCommitteeChange(boxed) => match mode {
                        Mode::Single => {
                            info!("Start proving");
                            let proof_handle = spawn_blocking(move || {
                                let (proving_mode, inputs) = *boxed;
                                committee_prover.prove(inputs, proving_mode)
                            });
                            let proof = proof_handle.await??;
                            info!("Proof generated. Serializing");
                            let proof_bytes = proof.to_bytes()?;
                            info!("Sending proof");
                            write_bytes(&mut client_stream, &proof_bytes).await?;
                            info!("Proof sent");
                        }
                        Mode::Split => {
                            let response = forward_request(&request_bytes, &snd_addr).await?;
                            info!("Received response from the secondary server. Sending result");
                            write_bytes(&mut client_stream, &response).await?;
                            info!("Response forwarded");
                        }
                    },
                    Request::VerifyCommitteeChange(proof) => match mode {
                        Mode::Single => {
                            write_bytes(
                                &mut client_stream,
                                &[u8::from(committee_prover.verify(&proof).is_ok())],
                            )
                            .await?;
                        }
                        Mode::Split => {
                            let response = forward_request(&request_bytes, &snd_addr).await?;
                            info!("Received response from the secondary server. Sending result");
                            write_bytes(&mut client_stream, &response).await?;
                            info!("Response forwarded");
                        }
                    },
                },
                Err(err) => error!("Failed to deserialize request object: {err}"),
            }
            Ok::<(), Error>(())
        });
    }
}

/// Forward the request to the secondary server and return the response.
///
/// # Arguments
///
/// * `request_bytes` - The request to forward.
/// * `snd_addr` - The address of the secondary server.
///
/// # Returns
///
/// The response from the secondary server.
async fn forward_request(request_bytes: &[u8], snd_addr: &str) -> Result<Vec<u8>> {
    info!("Connecting to the secondary server");
    let mut secondary_stream = TcpStream::connect(snd_addr).await?;
    info!("Sending secondary request");
    write_bytes(&mut secondary_stream, request_bytes).await?;
    info!("Awaiting response from secondary server");
    read_bytes(&mut secondary_stream).await
}
