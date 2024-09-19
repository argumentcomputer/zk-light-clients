// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::Response;
use axum::middleware::Next;
use axum::routing::post;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use clap::{Parser, ValueEnum};
use kadena_lc::proofs::spv::SpvProver;
use kadena_lc::proofs::Prover;
use kadena_lc::types::network::Request;
use log::{error, info};
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[derive(Clone)]
#[allow(dead_code)]
struct ServerState {
    snd_addr: Arc<Option<String>>,
    mode: Mode,
    active_requests: Arc<AtomicUsize>,
    longest_chain_prover: Arc<SpvProver>,
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
        snd_addr: Arc::new(snd_addr),
        mode,
        active_requests: Arc::new(AtomicUsize::new(0)),
        longest_chain_prover: Arc::new(SpvProver::new()),
    };

    let app = Router::new()
        .route("/spv/proof", post(spv_proof))
        .route("/spv/verify", post(spv_verify))
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
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

async fn spv_proof(
    State(state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = Request::from_bytes(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();
    let Request::ProveLongestChain(boxed) = request else {
        error!("Invalid request type");
        return Err(StatusCode::BAD_REQUEST);
    };

    let (proving_mode, inputs) = *boxed;
    let proof_handle =
        spawn_blocking(move || state.longest_chain_prover.prove(&inputs, proving_mode));
    let proof = proof_handle
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = proof
        .to_bytes()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

async fn spv_verify(
    State(state): State<ServerState>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = Request::from_bytes(&bytes);

    if let Err(err) = res {
        error!("Failed to deserialize request object: {err}");
        return Err(StatusCode::BAD_REQUEST);
    }

    let request = res.unwrap();
    let Request::VerifyLongestChain(boxed) = request else {
        error!("Invalid request type");
        return Err(StatusCode::BAD_REQUEST);
    };
    let res = {
        let is_valid = state.longest_chain_prover.verify(boxed.as_ref()).is_ok();
        vec![u8::from(is_valid)]
    };

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

#[allow(dead_code)]
async fn forward_request(request_bytes: &[u8], snd_addr: &str) -> Result<Vec<u8>, StatusCode> {
    info!("Connecting to the secondary server");
    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/proof", snd_addr))
        .body(request_bytes.to_vec())
        .header(CONTENT_TYPE, "application/octet-stream")
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    res.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn count_requests_middleware(
    State(state): State<ServerState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> std::result::Result<impl IntoResponse, StatusCode> {
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
