// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

//! # Primary server
//!
//! The primary server is responsible for handling requests regarding inclusion proofs. It is
//! capable of generating and verifying such proofs. Epoch change requests are offloaded to a
//! secondary server to ease the computational load necessary to handle inclusion proof requests.
//!
//! ## Usage
//!
//! For a detailed usage guide, please refer to the dedicated README in `aptos/docs/src/run/setup_proof_server.md`.

use anyhow::{Error, Result};
use aptos_lc::inclusion;
use clap::Parser;
use log::{error, info};
use sphinx_sdk::ProverClient;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    task::spawn_blocking,
};

use proof_server::{
    types::proof_server::{InclusionData, Request, SecondaryRequest},
    utils::{read_bytes, write_bytes},
};

/// Server responsible from handling requests for proof generation and verification
/// of inclusion and epoch changes.
///
/// Requests regarding epoch changes are offloaded to a secondary server in order
/// to ease the computation load necessary to handle requests regarding inclusion
/// proofs.
///
/// 1. Making requests to this server
///
/// From the client's perspective, before writing the request bytes on the stream,
/// the size of the request must be written as a big-endian 32 bits unsigned integer
/// so the server knows the size of the buffer it needs to allocate and how many
/// bytes is should read next.
///
/// The request bytes must be deserializable into `proof_server::Request` by the
/// `bcs` crate, so it's recommended to simply use that (pub) type when producing
/// request data.
///
/// Since request sizes must be expressible in 32 bits, the actual request payload
/// is bound by 4 GB, which should be way more than enough for the use case at hand.
///
/// 2. Handling responses from this server
///
/// Proofs are provided following the same logic as above: their sizes (in number
/// of bytes) must be read before reading the proof bytes themselves.
///
/// Verification responses are the same, with their payload only being a boolean.
#[derive(Parser)]
struct Cli {
    /// Address of this server. E.g. 127.0.0.1:1234
    #[arg(short, long)]
    addr: String,

    /// Address of the secondary server. E.g. 127.0.0.1:4321
    #[arg(long)]
    snd_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { addr, snd_addr } = Cli::parse();

    env_logger::init();

    let listener = TcpListener::bind(addr).await?;
    info!("Server is running on {}", listener.local_addr()?);

    let snd_addr = Arc::new(snd_addr);
    let prover_client = Arc::new(ProverClient::default());
    let (pk, vk) = inclusion::generate_keys(&prover_client);
    let (pk, vk) = (Arc::new(pk), Arc::new(vk));

    loop {
        let (mut client_stream, _) = listener.accept().await?;
        info!("Received a connection");

        // cheap `Arc` clones
        let snd_addr = snd_addr.clone();
        let prover_client = prover_client.clone();
        let pk = pk.clone();
        let vk = vk.clone();

        tokio::spawn(async move {
            info!("Awaiting request");
            let request_bytes = read_bytes(&mut client_stream).await?;
            info!("Request received");

            info!("Deserializing request");
            match bcs::from_bytes::<Request>(&request_bytes) {
                Ok(Request::ProveInclusion(inclusion_data)) => {
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
                    let proof_handle = spawn_blocking(move || prover_client.prove(&pk, stdin));
                    let proof = proof_handle.await??;
                    info!("Proof generated. Serializing");
                    let proof_bytes = bcs::to_bytes(&proof)?;
                    info!("Sending proof");
                    write_bytes(&mut client_stream, &proof_bytes).await?;
                    info!("Proof sent");
                }
                Ok(Request::VerifyInclusion(proof)) => {
                    write_bytes(
                        &mut client_stream,
                        &bcs::to_bytes(&prover_client.verify(&proof, &vk).is_ok())?,
                    )
                    .await?;
                }
                Ok(Request::ProveEpochChange(epoch_change_data)) => {
                    info!("Connecting to the secondary server");
                    let mut secondary_stream = TcpStream::connect(&*snd_addr).await?;
                    let secondary_request = SecondaryRequest::Prove(epoch_change_data);
                    info!("Serializing secondary request");
                    let secondary_request_bytes = bcs::to_bytes(&secondary_request)?;
                    info!("Sending secondary request");
                    write_bytes(&mut secondary_stream, &secondary_request_bytes).await?;
                    info!("Awaiting proof");
                    let proof_bytes = read_bytes(&mut secondary_stream).await?;
                    info!("Proof received. Sending it to the primary server");
                    write_bytes(&mut client_stream, &proof_bytes).await?;
                    info!("Proof sent");
                }
                Ok(Request::VerifyEpochChange(proof)) => {
                    info!("Connecting to the secondary server");
                    let mut secondary_stream = TcpStream::connect(&*snd_addr).await?;
                    let secondary_request = SecondaryRequest::Verify(proof);
                    info!("Serializing secondary request");
                    let secondary_request_bytes = bcs::to_bytes(&secondary_request)?;
                    info!("Sending secondary request");
                    write_bytes(&mut secondary_stream, &secondary_request_bytes).await?;
                    info!("Awaiting verification");
                    let verified = read_bytes(&mut secondary_stream).await?;
                    info!("Verification finished. Sending result");
                    write_bytes(&mut client_stream, &verified).await?;
                    info!("Verification result sent");
                }
                Ok(Request::Groth16ProveInclusion(inclusion_data)) => {
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
                    let proof_handle =
                        spawn_blocking(move || prover_client.prove_groth16(&pk, stdin));
                    let proof = proof_handle.await??;
                    info!("Proof generated. Serializing");
                    let proof_bytes = bcs::to_bytes(&proof)?;
                    info!("Sending proof");
                    write_bytes(&mut client_stream, &proof_bytes).await?;
                    info!("Proof sent");
                }
                Ok(Request::Groth16VerifyInclusion(proof)) => {
                    write_bytes(
                        &mut client_stream,
                        &bcs::to_bytes(&prover_client.verify_groth16(&proof, &vk).is_ok())?,
                    )
                    .await?;
                }
                Ok(Request::Groth16ProveEpochChange(epoch_change_data)) => {
                    info!("Connecting to the secondary server");
                    let mut secondary_stream = TcpStream::connect(&*snd_addr).await?;
                    let secondary_request = SecondaryRequest::Groth16Prove(epoch_change_data);
                    info!("Serializing secondary request");
                    let secondary_request_bytes = bcs::to_bytes(&secondary_request)?;
                    info!("Sending secondary request");
                    write_bytes(&mut secondary_stream, &secondary_request_bytes).await?;
                    info!("Awaiting proof");
                    let proof_bytes = read_bytes(&mut secondary_stream).await?;
                    info!("Proof received. Sending it to the primary server");
                    write_bytes(&mut client_stream, &proof_bytes).await?;
                    info!("Proof sent");
                }
                Ok(Request::Groth16VerifyEpochChange(proof)) => {
                    info!("Connecting to the secondary server");
                    let mut secondary_stream = TcpStream::connect(&*snd_addr).await?;
                    let secondary_request = SecondaryRequest::Groth16Verify(proof);
                    info!("Serializing secondary request");
                    let secondary_request_bytes = bcs::to_bytes(&secondary_request)?;
                    info!("Sending secondary request");
                    write_bytes(&mut secondary_stream, &secondary_request_bytes).await?;
                    info!("Awaiting verification");
                    let verified = read_bytes(&mut secondary_stream).await?;
                    info!("Verification finished. Sending result");
                    write_bytes(&mut client_stream, &verified).await?;
                    info!("Verification result sent");
                }
                Err(e) => error!("Failed to deserialize request object: {e}"),
            }
            Ok::<(), Error>(())
        });
    }
}
