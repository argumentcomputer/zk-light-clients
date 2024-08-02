// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use clap::Parser;
use ethereum_lc::proofs::committee_change::CommitteeChangeProver;
use ethereum_lc::proofs::Prover;
use ethereum_lc::types::network::Request;
use ethereum_lc::utils::{read_bytes, write_bytes};
use log::{error, info};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::spawn_blocking;

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
    let committee_prover = Arc::new(CommitteeChangeProver::new());

    loop {
        let (mut client_stream, _) = listener.accept().await?;
        info!("Received a connection");

        let committee_prover = committee_prover.clone();
        let snd_addr = snd_addr.clone();

        tokio::spawn(async move {
            info!("Awaiting request");
            let request_bytes = read_bytes(&mut client_stream).await?;
            info!("Request received");

            info!("Deserializing request");
            match Request::from_bytes(&request_bytes) {
                Ok(request) => match request {
                    Request::ProveCommitteeChange(boxed) => {
                        info!("Start proving");
                        let proof_handle = spawn_blocking(move || {
                            let (proving_mode, inputs) = *boxed;
                            committee_prover.prove(inputs, proving_mode)
                        });
                        let proof = proof_handle.await??;
                        info!("Proof generated. Serializing");
                        let proof_bytes = proof.to_bytes()?;
                        info!("Sending proof");
                        write_bytes(&mut client_stream, &proof_bytes).await?;
                        info!("Proof sent");
                    }
                    Request::VerifyCommitteeChange(proof) => {
                        write_bytes(
                            &mut client_stream,
                            &[u8::from(committee_prover.verify(&proof).is_ok())],
                        )
                        .await?;
                    }
                    Request::ProveInclusion(_) | Request::VerifyInclusion(_) => {
                        info!("Connecting to the secondary server");
                        let mut secondary_stream = TcpStream::connect(&*snd_addr).await?;
                        info!("Sending secondary request");
                        write_bytes(&mut secondary_stream, &request_bytes).await?;
                        info!("Awaiting response from secondary server");
                        let response = read_bytes(&mut secondary_stream).await?;
                        info!("Received response from the secondary server. Sending result");
                        write_bytes(&mut client_stream, &response).await?;
                        info!("Response forwarded");
                    }
                },
                Err(err) => error!("Failed to deserialize request object: {err}"),
            }
            Ok::<(), Error>(())
        });
    }
}
