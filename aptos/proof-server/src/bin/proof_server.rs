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
use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, ValueEnum};
use log::{error, info};
use proof_server::types::proof_server::EpochChangeData;
use proof_server::types::proof_server::{InclusionData, Request};
use serde::Deserialize;
use sphinx_sdk::{ProverClient, SphinxProofWithPublicValues, SphinxProvingKey, SphinxVerifyingKey};
use std::cmp::PartialEq;
use std::sync::Arc;
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

#[derive(Deserialize)]
struct ProofRequestPayload {
    request_bytes: Vec<u8>,
}

#[derive(Clone)]
struct ProofServerState {
    prover_client: Arc<ProverClient>,
    inclusion_pk: Arc<SphinxProvingKey>,
    inclusion_vk: Arc<SphinxVerifyingKey>,
    epoch_pk: Arc<SphinxProvingKey>,
    epoch_vk: Arc<SphinxVerifyingKey>,
    snd_addr: Arc<Option<String>>,
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

    let prover_client = Arc::new(ProverClient::default());
    let (inclusion_pk, inclusion_vk) = inclusion::generate_keys(&prover_client);
    let (epoch_pk, epoch_vk) = epoch_change::generate_keys(&prover_client);

    let state = ProofServerState {
        prover_client,
        inclusion_pk: Arc::new(inclusion_pk),
        inclusion_vk: Arc::new(inclusion_vk),
        epoch_pk: Arc::new(epoch_pk),
        epoch_vk: Arc::new(epoch_vk),
        snd_addr: Arc::new(snd_addr),
        mode,
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/proof", post(proof_handler))
        .with_state(state);

    info!("Server running on {}", addr);

    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_inclusion_proof(
    inclusion_data: InclusionData,
    snark: bool,
    prover_client: &Arc<ProverClient>,
    pk: &Arc<SphinxProvingKey>,
) -> Result<Vec<u8>, StatusCode> {
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
    let proof = proof_handle
        .await
        .map_err(|_| {
            error!("Failed to handle generate inclusion proof task");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|err| {
            error!("Failed to generate inclusion proof: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    info!("Proof generated. Serializing");
    let proof_bytes = bcs::to_bytes(&proof).map_err(|err| {
        error!("Failed to serialize epoch change proof: {err}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    info!("Sending proof");
    Ok(proof_bytes)
}

async fn handle_inclusion_verification(
    proof: &SphinxProofWithPublicValues,
    prover_client: &Arc<ProverClient>,
    vk: &Arc<SphinxVerifyingKey>,
) -> Result<Vec<u8>, StatusCode> {
    info!("Start verifying inclusion proof");

    let is_valid = prover_client.verify(proof, vk).is_ok();

    info!("Inclusion verification result: {}", is_valid);

    let verification_bytes = bcs::to_bytes(&is_valid).map_err(|_| {
        error!("Failed to serialize inclusion verification result");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(verification_bytes)
}

async fn handle_epoch_proof(
    epoch_change_data: EpochChangeData,
    snark: bool,
    prover_client: &Arc<ProverClient>,
    pk: &Arc<SphinxProvingKey>,
) -> Result<Vec<u8>, StatusCode> {
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
    let proof = proof_handle
        .await
        .map_err(|_| {
            error!("Failed to handle generate epoch change proof task");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|err| {
            error!("Failed to generate epoch change proof: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!("Epoch change proof generated. Serializing");
    let proof_bytes = bcs::to_bytes(&proof).map_err(|err| {
        error!("Failed to serialize epoch change proof: {err}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Sending epoch change proof");
    Ok(proof_bytes)
}

async fn handle_epoch_verification(
    proof: &SphinxProofWithPublicValues,
    prover_client: &Arc<ProverClient>,
    vk: &Arc<SphinxVerifyingKey>,
) -> Result<Vec<u8>, StatusCode> {
    info!("Start verifying epoch change proof");

    let is_valid = prover_client.verify(proof, vk).is_ok();

    info!("Epoch change verification result: {}", is_valid);

    let verification_bytes = bcs::to_bytes(&is_valid).map_err(|_| {
        error!("Failed to serialize epoch change verification result");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(verification_bytes)
}

async fn forward_request(request: Request, snd_addr: &str) -> Result<Vec<u8>, StatusCode> {
    info!("Connecting to the secondary server");
    let client = reqwest::Client::new();
    info!("Serializing secondary request");
    let secondary_request_bytes = bcs::to_bytes(&request).map_err(|err| {
        error!("Failed to serialize secondary request: {err}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    info!("Sending secondary request");
    let res_bytes = client
        .post(format!("http://{}/proof", snd_addr))
        .body(secondary_request_bytes)
        .send()
        .await
        .map_err(|err| {
            error!("Failed to send request to secondary server: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .bytes()
        .await
        .map_err(|err| {
            error!("Failed to receive response from secondary server: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!("Response received. Sending it to the client");

    Ok(res_bytes.to_vec())
}

async fn health_check() -> impl IntoResponse {
    "OK"
}

async fn proof_handler(
    State(state): State<ProofServerState>,
    Json(payload): Json<ProofRequestPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    let res = bcs::from_bytes::<Request>(&payload.request_bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        Err(StatusCode::BAD_REQUEST)
    } else {
        let request = res.unwrap();

        let res = match request {
            Request::ProveInclusion(inclusion_data) => {
                handle_inclusion_proof(
                    inclusion_data,
                    false,
                    &state.prover_client,
                    &state.inclusion_pk,
                )
                .await
            }
            Request::SnarkProveInclusion(inclusion_data) => {
                handle_inclusion_proof(
                    inclusion_data,
                    true,
                    &state.prover_client,
                    &state.inclusion_pk,
                )
                .await
            }
            Request::VerifyInclusion(proof) | Request::SnarkVerifyInclusion(proof) => {
                handle_inclusion_verification(&proof, &state.prover_client, &state.inclusion_vk)
                    .await
            }
            Request::ProveEpochChange(epoch_change_data) => match state.mode {
                Mode::Single => {
                    handle_epoch_proof(
                        epoch_change_data,
                        false,
                        &state.prover_client,
                        &state.epoch_pk,
                    )
                    .await
                }
                Mode::Split => {
                    forward_request(
                        Request::ProveEpochChange(epoch_change_data),
                        &state.snd_addr.as_ref().clone().unwrap(),
                    )
                    .await
                }
            },
            Request::SnarkProveEpochChange(epoch_change_data) => match state.mode {
                Mode::Single => {
                    handle_epoch_proof(
                        epoch_change_data,
                        true,
                        &state.prover_client,
                        &state.epoch_pk,
                    )
                    .await
                }
                Mode::Split => {
                    forward_request(
                        Request::SnarkProveEpochChange(epoch_change_data),
                        &state.snd_addr.as_ref().clone().unwrap(),
                    )
                    .await
                }
            },
            Request::SnarkVerifyEpochChange(proof) | Request::VerifyEpochChange(proof) => {
                match state.mode {
                    Mode::Single => {
                        handle_epoch_verification(&proof, &state.prover_client, &state.epoch_vk)
                            .await
                    }
                    Mode::Split => {
                        forward_request(
                            Request::VerifyEpochChange(proof.clone()),
                            &state.snd_addr.as_ref().clone().unwrap(),
                        )
                        .await
                    }
                }
            }
        }?;

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/x-bcs")
            .body(Body::from(res))
            .map_err(|err| {
                error!("Could not construct response for client: {err}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        Ok(response)
    }
}
