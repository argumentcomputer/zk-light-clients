// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use bcs::from_bytes;
use proof_server::error::ClientError;
use proof_server::types::aptos::{AccountInclusionProofResponse, EpochChangeProofResponse};
use proof_server::types::proof_server::{EpochChangeData, InclusionData, ProvingMode, Request};
use serde::Serialize;
use sphinx_sdk::install::try_install_plonk_bn254_artifacts;
use std::env;
use std::fs::File;
use std::io::Read;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize)]
struct BenchResults {
    e2e_proving_time: u128,
    inclusion_proof: ProofData,
    epoch_change_proof: ProofData,
    reconstruct_commitments: String,
    shard_size: String,
    shard_batch_size: String,
    shard_chunking_multiplier: String,
    rustflags: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProofData {
    proving_time: u128,
    request_response_proof_size: usize,
}

///
/// Those "default" values have been obtained empirically, e.g. by tuning Sphinx environment
/// variables and running the bench on r7iz.metal-16xl AWS EC2 instance
///
const ACCOUNT_INCLUSION_DATA_PATH: &str = "./benches/assets/account_inclusion_data.bcs";
const EPOCH_CHANGE_DATA_PATH: &str = "./benches/assets/epoch_change_data.bcs";
const DEFAULT_SNARK_SHARD_SIZE: &str = "4194304";
const DEFAULT_STARK_SHARD_SIZE: &str = "1048576";
const DEFAULT_SHARD_BATCH_SIZE: &str = "0";
const DEFAULT_STARK_SHARD_CHUNKING_MULTIPLIER: &str = "1";
const DEFAULT_SNARK_SHARD_CHUNKING_MULTIPLIER: &str = "64";
const DEFAULT_RUST_LOG: &str = "warn";
const DEFAULT_RUSTFLAGS: &str = "-C target-cpu=native --cfg tokio_unstable -C opt-level=3";
const DEFAULT_RECONSTRUCT_COMMITMENTS: &str = "false";

fn main() -> Result<(), anyhow::Error> {
    let final_snark: bool = env::var("SNARK").unwrap_or_else(|_| "0".into()) == "1";
    let run_parallel: bool = env::var("RUN_PARALLEL").unwrap_or_else(|_| "0".into()) == "1";

    let rust_log = env::var("RUST_LOG").ok();
    let shard_size = env::var("SHARD_SIZE").ok();
    let shard_batch_size = env::var("SHARD_BATCH_SIZE").ok();
    let shard_chunking_multiplier = env::var("SHARD_CHUNKING_MULTIPLIER").ok();
    let rustflags = env::var("RUSTFLAGS").ok();
    let reconstruct_commitments = env::var("RECONSTRUCT_COMMITMENTS").ok();

    let rt = Runtime::new().unwrap();

    if final_snark {
        // Install PLONK artifacts.
        try_install_plonk_bn254_artifacts();
    }

    // Start secondary server
    let mut secondary_server_process = rt.block_on(start_secondary_server(
        final_snark,
        rust_log.clone(),
        rustflags.clone(),
        shard_size.clone(),
        shard_batch_size.clone(),
        shard_chunking_multiplier.clone(),
        reconstruct_commitments.clone(),
    ))?;

    // Start primary server
    let mut primary_server_process = rt.block_on(start_primary_server(
        final_snark,
        rust_log.clone(),
        rustflags.clone(),
        shard_size.clone(),
        shard_batch_size.clone(),
        shard_chunking_multiplier.clone(),
        reconstruct_commitments.clone(),
    ))?;

    // Join the benchmark tasks and block until they are done
    let (res_inclusion_proof, res_epoch_change_proof) = if run_parallel {
        rt.block_on(async {
            let inclusion_proof_task = tokio::spawn(bench_proving_inclusion(final_snark));
            let epoch_change_proof_task = tokio::spawn(bench_proving_epoch_change(final_snark));

            let inclusion_proof = inclusion_proof_task.await.map_err(|e| anyhow!(e));
            let epoch_change_proof = epoch_change_proof_task.await.map_err(|e| anyhow!(e));

            (inclusion_proof, epoch_change_proof)
        })
    } else {
        rt.block_on(async {
            let inclusion_proof = bench_proving_inclusion(final_snark).await;
            let epoch_change_proof = bench_proving_epoch_change(final_snark).await;
            (Ok(inclusion_proof), Ok(epoch_change_proof))
        })
    };

    let inclusion_proof = res_inclusion_proof??;
    let epoch_change_proof = res_epoch_change_proof??;

    let e2e_proving_time = if inclusion_proof.proving_time > epoch_change_proof.proving_time {
        inclusion_proof.proving_time
    } else {
        epoch_change_proof.proving_time
    };

    let (
        _,
        reconstruct_commitments,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        rustflags,
    ) = get_actual_sphinx_parameters(
        final_snark,
        rust_log,
        rustflags,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        reconstruct_commitments,
    );

    let bench_results = BenchResults {
        e2e_proving_time,
        inclusion_proof,
        epoch_change_proof,
        reconstruct_commitments,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        rustflags,
    };

    let json_output = serde_json::to_string(&bench_results).unwrap();
    println!("{}", json_output);

    primary_server_process.kill().map_err(|e| anyhow!(e))?;
    secondary_server_process.kill().map_err(|e| anyhow!(e))?;

    Ok(())
}

fn get_actual_sphinx_parameters(
    final_snark: bool,
    rust_log: Option<String>,
    rustflags: Option<String>,
    shard_size: Option<String>,
    shard_batch_size: Option<String>,
    shard_chunking_multiplier: Option<String>,
    reconstruct_commitments: Option<String>,
) -> (String, String, String, String, String, String) {
    let shard_size = if final_snark {
        shard_size.unwrap_or(DEFAULT_SNARK_SHARD_SIZE.to_string())
    } else {
        shard_size.unwrap_or(DEFAULT_STARK_SHARD_SIZE.to_string())
    };

    let shard_chunking_multiplier = if final_snark {
        shard_chunking_multiplier.unwrap_or(DEFAULT_SNARK_SHARD_CHUNKING_MULTIPLIER.to_string())
    } else {
        shard_chunking_multiplier.unwrap_or(DEFAULT_STARK_SHARD_CHUNKING_MULTIPLIER.to_string())
    };

    let rust_log = rust_log.unwrap_or(DEFAULT_RUST_LOG.to_string());
    let rustflags = rustflags.unwrap_or(DEFAULT_RUSTFLAGS.to_string());
    let shard_batch_size = shard_batch_size.unwrap_or(DEFAULT_SHARD_BATCH_SIZE.to_string());
    let reconstruct_commitments =
        reconstruct_commitments.unwrap_or(DEFAULT_RECONSTRUCT_COMMITMENTS.to_string());

    (
        rust_log,
        reconstruct_commitments,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        rustflags,
    )
}

async fn start_primary_server(
    final_snark: bool,
    rust_log: Option<String>,
    rustflags: Option<String>,
    shard_size: Option<String>,
    shard_batch_size: Option<String>,
    shard_chunking_multiplier: Option<String>,
    reconstruct_commitments: Option<String>,
) -> Result<Child, anyhow::Error> {
    let primary_addr =
        env::var("PRIMARY_ADDR").map_err(|_| anyhow::anyhow!("PRIMARY_ADDR not set"))?;
    let secondary_addr =
        env::var("SECONDARY_ADDR").map_err(|_| anyhow::anyhow!("SECONDARY_ADDR not set"))?;

    let (
        rust_log,
        reconstruct_commitments,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        rustflags,
    ) = get_actual_sphinx_parameters(
        final_snark,
        rust_log,
        rustflags,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        reconstruct_commitments,
    );

    let process = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--bin",
            "proof_server",
            "--",
            "--mode",
            "split",
            "-a",
            &primary_addr,
            "--snd-addr",
            &secondary_addr,
        ])
        .env("RUST_LOG", rust_log)
        .env("RUSTFLAGS", rustflags)
        .env("SHARD_SIZE", shard_size)
        .env("SHARD_BATCH_SIZE", shard_batch_size)
        .env("SHARD_CHUNKING_MULTIPLIER", shard_chunking_multiplier)
        .env("RECONSTRUCT_COMMITMENTS", reconstruct_commitments)
        .spawn()
        .map_err(|e| anyhow!(e))?;

    let mut attempts = 0;

    loop {
        match TcpStream::connect(&primary_addr).await {
            Ok(_) => return Ok(process),
            Err(e) => {
                if attempts < 45 {
                    attempts += 1;
                    sleep(Duration::from_secs(1)).await;
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to connect to primary server: {}",
                        e
                    ));
                }
            }
        }
    }
}

async fn start_secondary_server(
    final_snark: bool,
    rust_log: Option<String>,
    rustflags: Option<String>,
    shard_size: Option<String>,
    shard_batch_size: Option<String>,
    shard_chunking_multiplier: Option<String>,
    reconstruct_commitments: Option<String>,
) -> Result<Child, anyhow::Error> {
    let secondary_addr =
        env::var("SECONDARY_ADDR").map_err(|_| anyhow::anyhow!("SECONDARY_ADDR not set"))?;

    let (
        rust_log,
        reconstruct_commitments,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        rustflags,
    ) = get_actual_sphinx_parameters(
        final_snark,
        rust_log,
        rustflags,
        shard_size,
        shard_batch_size,
        shard_chunking_multiplier,
        reconstruct_commitments,
    );

    let process = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--bin",
            "proof_server",
            "--",
            "--mode",
            "single",
            "-a",
            &secondary_addr,
        ])
        .env("RUST_LOG", rust_log)
        .env("RUSTFLAGS", rustflags)
        .env("SHARD_SIZE", shard_size)
        .env("SHARD_BATCH_SIZE", shard_batch_size)
        .env("SHARD_CHUNKING_MULTIPLIER", shard_chunking_multiplier)
        .env("RECONSTRUCT_COMMITMENTS", reconstruct_commitments)
        .spawn()
        .map_err(|e| anyhow!(e))?;

    let mut attempts = 0;

    loop {
        match TcpStream::connect(&secondary_addr).await {
            Ok(_) => return Ok(process),
            Err(e) => {
                if attempts < 45 {
                    attempts += 1;
                    sleep(Duration::from_secs(1)).await;
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to connect to secondary server: {}",
                        e
                    ));
                }
            }
        }
    }
}

async fn bench_proving_inclusion(final_snark: bool) -> Result<ProofData, anyhow::Error> {
    // Connect to primary server
    let primary_address =
        env::var("PRIMARY_ADDR").map_err(|_| anyhow::anyhow!("PRIMARY_ADDR not set"))?;
    let client = reqwest::Client::new();

    // Read the binary file
    let mut file = File::open(ACCOUNT_INCLUSION_DATA_PATH).map_err(|e| anyhow!(e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| anyhow!(e))?;

    // Deserialize the data into an AccountInclusionProofResponse structure
    let account_inclusion_proof_response: AccountInclusionProofResponse =
        from_bytes(&buffer).map_err(|e| anyhow!(e))?;

    // Convert the AccountInclusionProofResponse structure into an InclusionData structure
    let inclusion_data: InclusionData = account_inclusion_proof_response.into();

    // Send the InclusionData as a request payload to the primary server
    let proving_type = if final_snark {
        ProvingMode::SNARK
    } else {
        ProvingMode::STARK
    };
    let request_bytes = bcs::to_bytes(&Request::ProveInclusion(Box::new((
        proving_type,
        inclusion_data,
    ))))
    .map_err(|e| anyhow!(e))?;

    // Start measuring proving time
    let start = Instant::now();

    let response = client
        .post(format!("http://{primary_address}/inclusion/proof"))
        .header("Accept", "application/octet-stream")
        .body(request_bytes)
        .send()
        .await
        .map_err(|err| ClientError::Request {
            endpoint: primary_address,
            source: err.into(),
        })?;

    let response_bytes = response
        .bytes()
        .await
        .map_err(|err| ClientError::Internal { source: err.into() })?;

    Ok(ProofData {
        proving_time: start.elapsed().as_millis(),
        request_response_proof_size: response_bytes.len(),
    })
}

async fn bench_proving_epoch_change(final_snark: bool) -> Result<ProofData, anyhow::Error> {
    // Connect to primary server
    let primary_address =
        env::var("PRIMARY_ADDR").map_err(|_| anyhow::anyhow!("PRIMARY_ADDR not set"))?;
    let client = reqwest::Client::new();

    // Read the binary file
    let mut file = File::open(EPOCH_CHANGE_DATA_PATH).map_err(|e| anyhow!(e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| anyhow!(e))?;

    // Deserialize the data into an AccountInclusionProofResponse structure
    let account_inclusion_proof_response: EpochChangeProofResponse =
        from_bytes(&buffer).map_err(|e| anyhow!(e))?;

    // Convert the EpochChangeProofResponse structure into an EpochChangeData structure
    let epoch_change_data: EpochChangeData = account_inclusion_proof_response.into();

    // Send the InclusionData as a request payload to the primary server
    let proving_type = if final_snark {
        ProvingMode::SNARK
    } else {
        ProvingMode::STARK
    };
    let request_bytes = bcs::to_bytes(&Request::ProveEpochChange(Box::new((
        proving_type,
        epoch_change_data,
    ))))
    .map_err(|e| anyhow!(e))?;

    // Start measuring proving time
    let start = Instant::now();

    let response = client
        .post(format!("http://{primary_address}/epoch/proof"))
        .header("Accept", "application/octet-stream")
        .body(request_bytes)
        .send()
        .await
        .map_err(|err| ClientError::Request {
            endpoint: primary_address,
            source: err.into(),
        })?;

    let response_bytes = response
        .bytes()
        .await
        .map_err(|err| ClientError::Internal { source: err.into() })?;

    Ok(ProofData {
        proving_time: start.elapsed().as_millis(),
        request_response_proof_size: response_bytes.len(),
    })
}
