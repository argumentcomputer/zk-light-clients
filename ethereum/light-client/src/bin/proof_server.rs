// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::Response;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, ValueEnum};
use ethereum_lc::proofs::committee_change::CommitteeChangeProver;
use ethereum_lc::proofs::inclusion::StorageInclusionProver;
use ethereum_lc::proofs::Prover;
use ethereum_lc::types::network::Request;
use log::{error, info};
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpListener;
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

#[derive(Deserialize)]
struct ProofRequestPayload {
    request_bytes: Vec<u8>,
}

#[derive(Clone)]
struct ServerState {
    committee_prover: Arc<CommitteeChangeProver>,
    inclusion_prover: Arc<StorageInclusionProver>,
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

    let state = ServerState {
        committee_prover: Arc::new(CommitteeChangeProver::new()),
        inclusion_prover: Arc::new(StorageInclusionProver::new()),
        snd_addr: Arc::new(snd_addr),
        mode,
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/inclusion/proof", post(inclusion_proof))
        .route("/committee/proof", post(committee_proof))
        .route("/committee/verify", post(committee_verify))
        .route("/inclusion/verify", post(inclusion_verify))
        .with_state(state);

    info!("Server running on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    "OK"
}

async fn inclusion_proof(
    State(state): State<ServerState>,
    Json(payload): Json<ProofRequestPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    let res = Request::from_bytes(&payload.request_bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();
    let res = if let Request::ProveInclusion(boxed) = request {
        match state.mode {
            Mode::Single => {
                let (proving_mode, inputs) = *boxed;
                let proof_handle =
                    spawn_blocking(move || state.inclusion_prover.prove(&inputs, proving_mode));
                let proof = proof_handle
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                serde_json::to_vec(&proof).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            }
            Mode::Split => {
                let snd_addr = state.snd_addr.as_ref().clone().unwrap();
                forward_request(&payload.request_bytes, &snd_addr).await
            }
        }
    } else {
        error!("Invalid request type");
        Err(StatusCode::BAD_REQUEST)
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn committee_proof(
    State(state): State<ServerState>,
    Json(payload): Json<ProofRequestPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    let res = Request::from_bytes(&payload.request_bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();
    let res = if let Request::ProveCommitteeChange(boxed) = request {
        match state.mode {
            Mode::Single => {
                let (proving_mode, inputs) = *boxed;
                let proof_handle =
                    spawn_blocking(move || state.committee_prover.prove(&inputs, proving_mode));
                let proof = proof_handle
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                serde_json::to_vec(&proof).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            }
            Mode::Split => {
                let snd_addr = state.snd_addr.as_ref().clone().unwrap();
                forward_request(&payload.request_bytes, &snd_addr).await
            }
        }
    } else {
        error!("Invalid request type");
        Err(StatusCode::BAD_REQUEST)
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn inclusion_verify(
    State(state): State<ServerState>,
    Json(payload): Json<ProofRequestPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    let res = Request::from_bytes(&payload.request_bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();
    let res = if let Request::VerifyInclusion(proof) = request {
        let is_valid = state.inclusion_prover.verify(&proof).is_ok();
        serde_json::to_vec(&is_valid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        error!("Invalid request type");
        Err(StatusCode::BAD_REQUEST)
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn committee_verify(
    State(state): State<ServerState>,
    Json(payload): Json<ProofRequestPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    let res = Request::from_bytes(&payload.request_bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();
    let res = if let Request::VerifyCommitteeChange(proof) = request {
        let is_valid = state.committee_prover.verify(&proof).is_ok();
        serde_json::to_vec(&is_valid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        error!("Invalid request type");
        Err(StatusCode::BAD_REQUEST)
    }?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(res))
        .map_err(|err| {
            error!("Could not construct response for client: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

async fn forward_request(request_bytes: &[u8], snd_addr: &str) -> Result<Vec<u8>, StatusCode> {
    info!("Connecting to the secondary server");
    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/proof", snd_addr))
        .body(request_bytes.to_vec())
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    res.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
