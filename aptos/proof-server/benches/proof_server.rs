// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use anyhow::anyhow;
use bcs::from_bytes;
use proof_server::types::aptos::{AccountInclusionProofResponse, EpochChangeProofResponse};
use proof_server::types::proof_server::{EpochChangeData, InclusionData, Request};
use proof_server::utils::{read_bytes, write_bytes};
use serde::Serialize;
use sphinx_sdk::artifacts::try_install_plonk_bn254_artifacts;
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
}

#[derive(Debug, Clone, Serialize)]

struct ProofData {
    proving_time: u128,
    request_response_proof_size: usize,
}

const ACCOUNT_INCLUSION_DATA_PATH: &str = "./benches/assets/account_inclusion_data.bcs";
const EPOCH_CHANGE_DATA_PATH: &str = "./benches/assets/epoch_change_data.bcs";
const SNARK_SHARD_SIZE: &str = "4194304";
const STARK_SHARD_SIZE: &str = "1048576";
const SHARD_BATCH_SIZE: &str = "0";
const RUST_LOG: &str = "warn";
const RUSTFLAGS: &str = "-C target-cpu=native --cfg tokio_unstable -C opt-level=3";

fn main() -> Result<(), anyhow::Error> {
    let final_snark: bool = env::var("SNARK").unwrap_or_else(|_| "0".into()) == "1";
    let run_parallel: bool = env::var("RUN_PARALLEL").unwrap_or_else(|_| "0".into()) == "1";

    let rt = Runtime::new().unwrap();

    if final_snark {
        // Install PLONK artifacts.
        try_install_plonk_bn254_artifacts(false);
    }

    // Start secondary server
    let mut secondary_server_process = rt.block_on(start_secondary_server(final_snark))?;

    // Start primary server
    let mut primary_server_process = rt.block_on(start_primary_server(final_snark))?;

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

    let bench_results = BenchResults {
        e2e_proving_time,
        inclusion_proof,
        epoch_change_proof,
    };

    let json_output = serde_json::to_string(&bench_results).unwrap();
    println!("{}", json_output);

    primary_server_process.kill().map_err(|e| anyhow!(e))?;
    secondary_server_process.kill().map_err(|e| anyhow!(e))?;

    Ok(())
}

async fn start_primary_server(final_snark: bool) -> Result<Child, anyhow::Error> {
    let primary_addr =
        env::var("PRIMARY_ADDR").map_err(|_| anyhow::anyhow!("PRIMARY_ADDR not set"))?;
    let secondary_addr =
        env::var("SECONDARY_ADDR").map_err(|_| anyhow::anyhow!("SECONDARY_ADDR not set"))?;

    let shard_size = if final_snark {
        SNARK_SHARD_SIZE
    } else {
        STARK_SHARD_SIZE
    };

    let process = Command::new("cargo")
        .args([
            "+nightly-2024-05-31",
            "run",
            "--release",
            "--bin",
            "server_primary",
            "--",
            "-a",
            &primary_addr,
            "--snd-addr",
            &secondary_addr,
        ])
        .env("RUST_LOG", RUST_LOG)
        .env("RUSTFLAGS", RUSTFLAGS)
        .env("SHARD_SIZE", shard_size)
        .env("SHARD_BATCH_SIZE", SHARD_BATCH_SIZE)
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

async fn start_secondary_server(final_snark: bool) -> Result<Child, anyhow::Error> {
    let secondary_addr =
        env::var("SECONDARY_ADDR").map_err(|_| anyhow::anyhow!("SECONDARY_ADDR not set"))?;

    let shard_size = if final_snark {
        SNARK_SHARD_SIZE
    } else {
        STARK_SHARD_SIZE
    };

    let process = Command::new("cargo")
        .args([
            "+nightly-2024-05-31",
            "run",
            "--release",
            "--bin",
            "server_secondary",
            "--",
            "-a",
            &secondary_addr,
        ])
        .env("RUST_LOG", RUST_LOG)
        .env("RUSTFLAGS", RUSTFLAGS)
        .env("SHARD_SIZE", shard_size)
        .env("SHARD_BATCH_SIZE", SHARD_BATCH_SIZE)
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
    let mut tcp_stream = TcpStream::connect(primary_address)
        .await
        .map_err(|e| anyhow!(e))?;

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
    let request_bytes = if final_snark {
        bcs::to_bytes(&Request::SnarkProveInclusion(inclusion_data)).map_err(|e| anyhow!(e))?
    } else {
        bcs::to_bytes(&Request::ProveInclusion(inclusion_data)).map_err(|e| anyhow!(e))?
    };

    write_bytes(&mut tcp_stream, &request_bytes)
        .await
        .map_err(|e| anyhow!(e))?;

    // Start measuring proving time
    let start = Instant::now();

    // Measure the time taken to get a response and the size of the response payload
    let response_bytes = read_bytes(&mut tcp_stream).await.map_err(|e| anyhow!(e))?;

    Ok(ProofData {
        proving_time: start.elapsed().as_millis(),
        request_response_proof_size: response_bytes.len(),
    })
}

async fn bench_proving_epoch_change(final_snark: bool) -> Result<ProofData, anyhow::Error> {
    // Connect to primary server
    let primary_address =
        env::var("PRIMARY_ADDR").map_err(|_| anyhow::anyhow!("PRIMARY_ADDR not set"))?;
    let mut tcp_stream = TcpStream::connect(primary_address)
        .await
        .map_err(|e| anyhow!(e))?;

    // Read the binary file
    let mut file = File::open(EPOCH_CHANGE_DATA_PATH).map_err(|e| anyhow!(e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| anyhow!(e))?;

    // Deserialize the data into an AccountInclusionProofResponse structure
    let account_inclusion_proof_response: EpochChangeProofResponse =
        from_bytes(&buffer).map_err(|e| anyhow!(e))?;

    // Convert the EpochChangeProofResponse structure into an EpochChangeData structure
    let inclusion_data: EpochChangeData = account_inclusion_proof_response.into();

    // Send the InclusionData as a request payload to the primary server
    let request_bytes = if final_snark {
        bcs::to_bytes(&Request::SnarkProveEpochChange(inclusion_data)).map_err(|e| anyhow!(e))?
    } else {
        bcs::to_bytes(&Request::ProveEpochChange(inclusion_data)).map_err(|e| anyhow!(e))?
    };

    write_bytes(&mut tcp_stream, &request_bytes)
        .await
        .map_err(|e| anyhow!(e))?;

    // Start measuring proving time
    let start = Instant::now();

    // Measure the time taken to get a response and the size of the response payload
    let response_bytes = read_bytes(&mut tcp_stream).await.map_err(|e| anyhow!(e))?;

    Ok(ProofData {
        proving_time: start.elapsed().as_millis(),
        request_response_proof_size: response_bytes.len(),
    })
}
