// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use clap::Parser;
use ethereum_lc::proofs::inclusion::StorageInclusionProver;
use ethereum_lc::proofs::Prover;
use ethereum_lc::types::network::Request;
use ethereum_lc::utils::{read_bytes, write_bytes};
use log::{error, info};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::spawn_blocking;

#[derive(Parser)]
struct Cli {
    /// Address of this server. E.g. 127.0.0.1:4321
    #[arg(short, long)]
    addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { addr } = Cli::parse();

    env_logger::init();

    let listener = TcpListener::bind(addr).await?;

    info!("Server is running on {}", listener.local_addr()?);

    let inclusion_prover = Arc::new(StorageInclusionProver::new());

    loop {
        let (mut client_stream, _) = listener.accept().await?;
        info!("Received a connection");

        let inclusion_prover = inclusion_prover.clone();

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
                            let (proving_mode, inputs) = boxed.as_ref();
                            inclusion_prover.prove(inputs.clone(), proving_mode.clone())
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
                    _ => {
                        error!("Received unexpected request object, secondary server only handles inclusion proofs")
                    }
                },
                Err(err) => error!("Failed to deserialize request object: {err}"),
            }
            Ok::<(), Error>(())
        });
    }
}
