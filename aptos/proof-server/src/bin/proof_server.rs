// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Server secondary
//!
//! Server capable of handling proof generation and verification regarding epoch changes. Such
//! requests are expected to come from the primary server.
//!
//! ## Usage
//!
//! For a detailed usage guide, please refer to the dedicated README in `aptos/docs/src/run/setup_proof_server.md`.

use anyhow::{Error, Result};
use aptos_lc::{epoch_change, inclusion};
use clap::{Parser, ValueEnum};
use log::{error, info};
use proof_server::types::proof_server::{InclusionData, Request};
use proof_server::{
    types::proof_server::EpochChangeData,
    utils::{read_bytes, write_bytes},
};
use sphinx_sdk::{ProverClient, SphinxProofWithPublicValues, SphinxProvingKey, SphinxVerifyingKey};
use std::cmp::PartialEq;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::{net::TcpListener, task::spawn_blocking};

#[derive(ValueEnum, Clone, Debug, Eq, PartialEq)]
enum Mode {
    Single,
    Split,
}

/// Server capable of handling proof generation and verification regarding epoch
/// changes. Such requests are expected to come from the primary server.
///
/// Making requests to this server and handling responses from it follows the
/// same logic from the primary server:
///
/// * Request data must be preceded by its size in bytes
/// * Proof responses will follow the same logic
/// * Verification responses will follow the same logic.
///
/// The request bytes must be deserializable into `proof_server::SecondaryRequest`
/// by the `bcs` crate, so it's recommended to simply use that (pub) type when
/// producing request data.
#[derive(Parser)]
struct Cli {
    /// Address of this server. E.g. 127.0.0.1:4321
    #[arg(short, long)]
    addr: String,

    /// Address of the secondary server. E.g. 127.0.0.1:4321
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

    let prover_client = Arc::new(ProverClient::default());
    let (inclusion_pk, inclusion_vk) = inclusion::generate_keys(&prover_client);
    let (epoch_pk, epoch_vk) = epoch_change::generate_keys(&prover_client);
    let (inclusion_pk, inclusion_vk) = (Arc::new(inclusion_pk), Arc::new(inclusion_vk));
    let (epoch_pk, epoch_vk) = (Arc::new(epoch_pk), Arc::new(epoch_vk));

    loop {
        let (mut client_stream, _) = listener.accept().await?;
        info!("Received a connection");

        let prover_client = prover_client.clone();
        let inclusion_pk = inclusion_pk.clone();
        let inclusion_vk = inclusion_vk.clone();
        let epoch_pk = epoch_pk.clone();
        let epoch_vk = epoch_vk.clone();

        let snd_addr = snd_addr.clone();
        let mode = mode.clone();

        tokio::spawn(async move {
            info!("Awaiting request");
            let request_bytes = read_bytes(&mut client_stream).await?;
            info!("Request received");

            info!("Deserializing request");
            match bcs::from_bytes::<Request>(&request_bytes) {
                Ok(Request::ProveInclusion(inclusion_data)) => {
                    handle_inclusion_proof(
                        inclusion_data,
                        false,
                        &mut client_stream,
                        &prover_client,
                        &inclusion_pk,
                    )
                    .await?;
                }
                Ok(Request::SnarkProveInclusion(inclusion_data)) => {
                    handle_inclusion_proof(
                        inclusion_data,
                        true,
                        &mut client_stream,
                        &prover_client,
                        &inclusion_pk,
                    )
                    .await?;
                }
                Ok(Request::VerifyInclusion(proof) | Request::SnarkVerifyInclusion(proof)) => {
                    handle_inclusion_verification(
                        &proof,
                        &mut client_stream,
                        &prover_client,
                        &inclusion_vk,
                    )
                    .await?;
                }
                Ok(Request::ProveEpochChange(epoch_change_data)) => match mode {
                    Mode::Single => {
                        handle_epoch_proof(
                            epoch_change_data,
                            false,
                            &mut client_stream,
                            &prover_client,
                            &epoch_pk,
                        )
                        .await?;
                    }
                    Mode::Split => {
                        forward_request(
                            Request::ProveEpochChange(epoch_change_data),
                            snd_addr.as_ref().unwrap(),
                            &mut client_stream,
                        )
                        .await?;
                    }
                },

                Ok(Request::SnarkProveEpochChange(epoch_change_data)) => match mode {
                    Mode::Single => {
                        handle_epoch_proof(
                            epoch_change_data,
                            true,
                            &mut client_stream,
                            &prover_client,
                            &epoch_pk,
                        )
                        .await?;
                    }
                    Mode::Split => {
                        forward_request(
                            Request::SnarkProveEpochChange(epoch_change_data),
                            snd_addr.as_ref().unwrap(),
                            &mut client_stream,
                        )
                        .await?;
                    }
                },
                Ok(Request::SnarkVerifyEpochChange(proof) | Request::VerifyEpochChange(proof)) => {
                    match mode {
                        Mode::Single => {
                            handle_epoch_verification(
                                &proof,
                                &mut client_stream,
                                &prover_client,
                                &epoch_vk,
                            )
                            .await?;
                        }
                        Mode::Split => {
                            forward_request(
                                Request::VerifyEpochChange(proof.clone()),
                                snd_addr.as_ref().unwrap(),
                                &mut client_stream,
                            )
                            .await?;
                        }
                    }
                }
                Err(e) => error!("Failed to deserialize request object: {e}"),
            }
            Ok::<(), Error>(())
        });
    }
}

async fn handle_inclusion_proof(
    inclusion_data: InclusionData,
    snark: bool,
    client_stream: &mut TcpStream,
    prover_client: &Arc<ProverClient>,
    pk: &Arc<SphinxProvingKey>,
) -> Result<()> {
    let InclusionData {
        sparse_merkle_proof_assets,
        transaction_proof_assets,
        validator_verifier_assets,
    } = inclusion_data;
    let stdin = inclusion::generate_stdin(
        &sparse_merkle_proof_assets,
        &transaction_proof_assets,
        &validator_verifier_assets,
    );
    info!("Start proving");

    let prover_client = Arc::clone(prover_client);
    let pk = Arc::clone(pk);

    let proof_handle = if snark {
        spawn_blocking(move || prover_client.prove(&pk, stdin).plonk().run())
    } else {
        spawn_blocking(move || prover_client.prove(&pk, stdin).run())
    };
    let proof = proof_handle.await??;
    info!("Proof generated. Serializing");
    let proof_bytes = bcs::to_bytes(&proof)?;
    info!("Sending proof");
    write_bytes(client_stream, &proof_bytes).await?;
    info!("Proof sent");
    Ok(())
}

async fn handle_inclusion_verification(
    proof: &SphinxProofWithPublicValues,
    client_stream: &mut TcpStream,
    prover_client: &Arc<ProverClient>,
    vk: &Arc<SphinxVerifyingKey>,
) -> Result<()> {
    let is_valid = prover_client.verify(proof, vk).is_ok();
    write_bytes(client_stream, &bcs::to_bytes(&is_valid)?).await?;
    Ok(())
}

async fn handle_epoch_proof(
    epoch_change_data: EpochChangeData,
    snark: bool,
    client_stream: &mut TcpStream,
    prover_client: &Arc<ProverClient>,
    pk: &Arc<SphinxProvingKey>,
) -> Result<()> {
    let EpochChangeData {
        trusted_state,
        epoch_change_proof,
    } = epoch_change_data;

    let stdin = epoch_change::generate_stdin(&trusted_state, &epoch_change_proof);
    info!("Start proving epoch change");

    let prover_client = Arc::clone(prover_client);
    let pk = Arc::clone(pk);

    let proof_handle = if snark {
        spawn_blocking(move || prover_client.prove(&pk, stdin).plonk().run())
    } else {
        spawn_blocking(move || prover_client.prove(&pk, stdin).run())
    };
    let proof = proof_handle.await??;

    info!("Epoch change proof generated. Serializing");
    let proof_bytes = bcs::to_bytes(&proof)?;

    info!("Sending epoch change proof");
    write_bytes(client_stream, &proof_bytes).await?;
    info!("Epoch change proof sent");

    Ok(())
}

async fn handle_epoch_verification(
    proof: &SphinxProofWithPublicValues,
    client_stream: &mut TcpStream,
    prover_client: &Arc<ProverClient>,
    vk: &Arc<SphinxVerifyingKey>,
) -> Result<()> {
    info!("Start verifying epoch change proof");

    let is_valid = prover_client.verify(proof, vk).is_ok();

    info!("Epoch change verification result: {}", is_valid);
    let verification_bytes = bcs::to_bytes(&is_valid)?;

    info!("Sending epoch change verification result");
    write_bytes(client_stream, &verification_bytes).await?;
    info!("Epoch change verification result sent");

    Ok(())
}

async fn forward_request(
    request: Request,
    snd_addr: &str,
    client_stream: &mut TcpStream,
) -> Result<()> {
    info!("Connecting to the secondary server");
    let mut secondary_stream = TcpStream::connect(snd_addr).await?;
    info!("Serializing secondary request");
    let secondary_request_bytes = bcs::to_bytes(&request)?;
    info!("Sending secondary request");
    write_bytes(&mut secondary_stream, &secondary_request_bytes).await?;
    info!("Awaiting response");
    let response_bytes = read_bytes(&mut secondary_stream).await?;
    info!("Response received. Sending it to the client");
    write_bytes(client_stream, &response_bytes).await?;
    info!("Response sent");
    Ok(())
}
