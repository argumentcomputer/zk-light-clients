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
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use clap::{Parser, ValueEnum};
use log::{error, info};
use proof_server::types::proof_server::{EpochChangeData, ProvingMode};
use proof_server::types::proof_server::{InclusionData, Request};
use sphinx_sdk::{ProverClient, SphinxProvingKey, SphinxVerifyingKey};
use std::cmp::PartialEq;
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[derive(Clone)]
struct ServerState {
    prover_client: Arc<ProverClient>,
    inclusion_pk: Arc<SphinxProvingKey>,
    inclusion_vk: Arc<SphinxVerifyingKey>,
    epoch_pk: Arc<SphinxProvingKey>,
    epoch_vk: Arc<SphinxVerifyingKey>,
    snd_addr: Arc<Option<String>>,
    mode: Mode,
    active_requests: Arc<AtomicUsize>,
}

#[allow(clippy::needless_return)]
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

    let state = ServerState {
        prover_client,
        inclusion_pk: Arc::new(inclusion_pk),
        inclusion_vk: Arc::new(inclusion_vk),
        epoch_pk: Arc::new(epoch_pk),
        epoch_vk: Arc::new(epoch_vk),
        snd_addr: Arc::new(snd_addr),
        mode,
        active_requests: Arc::new(AtomicUsize::new(0)),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .route("/inclusion/proof", post(inclusion_proof))
        .route("/epoch/proof", post(epoch_proof))
        .route("/epoch/verify", post(epoch_verify))
        .route("/inclusion/verify", post(inclusion_verify))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            count_requests_middleware,
        ))
        .with_state(state);

    info!("Server running on {}", addr);

    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}

async fn ready_check(State(state): State<ServerState>) -> impl IntoResponse {
    let active_requests = state.active_requests.load(Ordering::SeqCst);
    if active_requests > 0 {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    }
}

async fn inclusion_proof(
    State(state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = bcs::from_bytes::<Request>(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();

    let Request::ProveInclusion(boxed) = request else {
        error!("Invalid request type");
        return Err(StatusCode::BAD_REQUEST);
    };
    let res = {
        info!("Start proving");

        let (proof_type, inclusion_data) = boxed.as_ref();
        let InclusionData {
            sparse_merkle_proof_assets,
            transaction_proof_assets,
            validator_verifier_assets,
        } = inclusion_data;
        let stdin = inclusion::generate_stdin(
            sparse_merkle_proof_assets,
            transaction_proof_assets,
            validator_verifier_assets,
        );

        let prover_client = state.prover_client.clone();
        let pk = state.inclusion_pk.clone();

        let proof_handle = if proof_type == &ProvingMode::SNARK {
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
        bcs::to_bytes(&proof).map_err(|err| {
            error!("Failed to serialize epoch change proof: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn inclusion_verify(
    State(state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = bcs::from_bytes::<Request>(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();

    let Request::VerifyInclusion(proof) = request else {
        error!("Invalid request type");
        return Err(StatusCode::BAD_REQUEST);
    };
    let res = {
        info!("Start verifying inclusion proof");

        let is_valid = state
            .prover_client
            .verify(&proof, &state.inclusion_vk)
            .is_ok();

        info!("Inclusion verification result: {}", is_valid);

        bcs::to_bytes(&is_valid).map_err(|_| {
            error!("Failed to serialize inclusion verification result");
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn epoch_proof(
    State(state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = bcs::from_bytes::<Request>(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();

    let Request::ProveEpochChange(boxed) = request else {
        error!("Invalid request type");
        return Err(StatusCode::BAD_REQUEST);
    };
    let res = {
        match state.mode {
            Mode::Single => {
                let (proof_type, epoch_change_data) = boxed.as_ref();

                let EpochChangeData {
                    trusted_state,
                    epoch_change_proof,
                } = epoch_change_data;

                let stdin = epoch_change::generate_stdin(trusted_state, epoch_change_proof);
                info!("Start proving epoch change");

                let prover_client = state.prover_client.clone();
                let pk = state.epoch_pk.clone();

                let proof_handle = if proof_type == &ProvingMode::SNARK {
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
                bcs::to_bytes(&proof).map_err(|err| {
                    error!("Failed to serialize epoch change proof: {err}");
                    StatusCode::INTERNAL_SERVER_ERROR
                })
            }
            Mode::Split => {
                let snd_addr = state.snd_addr.as_ref().clone().unwrap();
                forward_request(bytes.to_vec(), &snd_addr).await
            }
        }
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn epoch_verify(
    State(state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    info!("Start verifying epoch change proof");

    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = bcs::from_bytes::<Request>(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();

    let Request::VerifyEpochChange(proof) = request else {
        error!("Invalid request type");
        return Err(StatusCode::BAD_REQUEST);
    };
    let res = {
        let is_valid = state.prover_client.verify(&proof, &state.epoch_vk).is_ok();

        info!("Epoch change verification result: {}", is_valid);

        bcs::to_bytes(&is_valid).map_err(|_| {
            error!("Failed to serialize epoch change verification result");
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn forward_request(
    secondary_request_bytes: Vec<u8>,
    snd_addr: &str,
) -> Result<Vec<u8>, StatusCode> {
    info!("Connecting to the secondary server");
    let client = reqwest::Client::new();
    info!("Sending secondary request");
    let res_bytes = client
        .post(format!("http://{}/epoch/proof", snd_addr))
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

async fn count_requests_middleware(
    State(state): State<ServerState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let is_ready = req.uri().path() != "/ready";
    // Check if the request is for the ready endpoint.
    if is_ready {
        // Increment the active requests counter.
        state.active_requests.fetch_add(1, Ordering::SeqCst);
    }

    // Proceed with the request.
    let response = next.run(req).await;

    // Decrement the active requests counter if not a ready check.
    if is_ready {
        state.active_requests.fetch_sub(1, Ordering::SeqCst);
    }

    Ok(response)
}
