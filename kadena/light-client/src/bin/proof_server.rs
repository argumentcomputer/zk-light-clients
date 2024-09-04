// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use clap::{Parser, ValueEnum};
use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

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
    };

    let app = Router::new()
        .route("/health", get(health_check))
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

async fn health_check(State(state): State<ServerState>) -> impl IntoResponse {
    let active_requests = state.active_requests.load(Ordering::SeqCst);
    if active_requests > 0 {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    }
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
) -> Result<impl IntoResponse, StatusCode> {
    let is_health = req.uri().path() != "/health";
    // Check if the request is for the health endpoint.
    if is_health {
        // Increment the active requests counter.
        state.active_requests.fetch_add(1, Ordering::SeqCst);
    }

    // Proceed with the request.
    let response = next.run(req).await;

    // Decrement the active requests counter if not a health check.
    if is_health {
        state.active_requests.fetch_sub(1, Ordering::SeqCst);
    }

    Ok(response)
}
