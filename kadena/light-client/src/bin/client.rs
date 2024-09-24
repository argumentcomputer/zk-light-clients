// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;
use kadena_lc::client::error::ClientError;
use kadena_lc::client::Client;
use kadena_lc::proofs::longest_chain::LongestChainOut;
use kadena_lc::proofs::spv::SpvOut;
use kadena_lc::proofs::{ProofType, ProvingMode};
use kadena_lc_core::crypto::hash::HashValue;
use kadena_lc_core::crypto::U256;
use kadena_lc_core::merkle::spv::Spv;
use log::{error, info};
use std::env;
use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinHandle;

pub const CHECKPOINT_BLOCK_HEIGHT: usize = 5156900;
pub const BLOCK_WINDOW: usize = 3;
pub const VERIFIER_STORED_CHECKPOINT_COUNT: usize = 5;
pub const CONFIRMATION_WORK_THRESHOLD: usize = 0;

/// The CLI for the light client.
#[derive(Parser)]
struct Cli {
    /// The address of the chainweb node API.
    #[arg(short, long)]
    chainweb_node_address: String,

    /// The address of the proof server
    #[arg(short, long)]
    proof_server_address: String,
}

#[derive(Debug, Clone)]
pub struct LightClientState {
    current_block_height: usize,
}

impl Default for LightClientState {
    fn default() -> Self {
        Self {
            current_block_height: CHECKPOINT_BLOCK_HEIGHT,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifierState {
    validated_layer_hash: [HashValue; VERIFIER_STORED_CHECKPOINT_COUNT],
    confirmation_work_threshold: U256,
}

pub enum VerificationTask {
    LongestChain {
        task: JoinHandle<Result<ProofType, ClientError>>,
        permit: OwnedSemaphorePermit,
    },
    Spv {
        task: JoinHandle<Result<(Box<Spv>, ProofType), ClientError>>,
        permit: OwnedSemaphorePermit,
    },
}

impl VerificationTask {
    pub fn task_finished(&self) -> bool {
        match self {
            VerificationTask::LongestChain { task, .. } => task.is_finished(),
            VerificationTask::Spv { task, .. } => task.is_finished(),
        }
    }
}

impl Display for &VerificationTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationTask::LongestChain { .. } => write!(f, "Longest Chain"),
            VerificationTask::Spv { .. } => write!(f, "SPV"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Get proving mode for the light client.
    let mode_str: String = env::var("MODE").unwrap_or_else(|_| "STARK".into());
    let mode = ProvingMode::try_from(mode_str.as_str()).expect("MODE should be STARK or SNARK");

    // Extract all addresses from the command.
    let Cli {
        chainweb_node_address,
        proof_server_address,
        ..
    } = Cli::parse();

    // Initialize the logger.
    env_logger::init();

    let mode = Arc::new(mode);
    let proof_server_address = Arc::new(proof_server_address);
    let chainweb_node_address = Arc::new(chainweb_node_address);

    let (client, lc_state, verifier_state) = initialize_light_client(
        mode,
        chainweb_node_address.clone(),
        proof_server_address.clone(),
    )
    .await
    .expect("Failed to initialize light client");

    let store = Arc::new(RwLock::new(lc_state));
    let client = Arc::new(client);

    info!("Light client initialized successfully");

    // Create a Semaphore with only one permit for the proofs process.
    let longest_chain_semaphore = Arc::new(Semaphore::new(1));
    let spv_semaphore = Arc::new(Semaphore::new(1));

    info!("Spawn verifier task");
    let (task_sender, task_receiver) = mpsc::channel::<VerificationTask>(100);
    let task_sender = Arc::new(task_sender);

    // Start the main loop to listen for Eth data every 10 seconds.
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    // Spawn a verifier task that sequentially processes the tasks.
    tokio::spawn(verifier_task(
        task_sender.clone(),
        task_receiver,
        verifier_state,
        client.clone(),
        store.clone(),
    ));
    /*
    let client = Client::new(
        chainweb_node_address.as_str(),
        proof_server_address.as_str(),
    );

    let header = client.get_block_header(0, CHECKPOINT_BLOCK_HEIGHT).await?;
    dbg!(header.decoded_height());

    // Test verification for the longest chain
    let kadena_headers = client
        .get_layer_block_headers(CHECKPOINT_BLOCK_HEIGHT, BLOCK_WINDOW)
        .await?;

    let (first_hash, target_hash, verified_confirmation_work) =
        ChainwebLayerHeader::verify(&kadena_headers)?;

    let confirmation_work = ChainwebLayerHeader::cumulative_produced_work(
        kadena_headers[kadena_headers.len() / 2..kadena_headers.len() - 1].to_vec(),
    )
    .expect("Should be able to calculate cumulative work");

    assert_eq!(confirmation_work, verified_confirmation_work,);
    assert_eq!(
        first_hash,
        kadena_headers
            .first()
            .expect("Should have a first header")
            .header_root()
            .expect("Should have a header root"),
    );
    assert_eq!(
        target_hash,
        kadena_headers[kadena_headers.len() / 2]
            .header_root()
            .expect("Should have a header root"),
    );

    let target_block = kadena_headers
        .get(kadena_headers.len() / 2)
        .unwrap()
        .clone();

    let payload = client
        .get_payload(
            0,
            HashValue::new(*target_block.chain_headers().first().unwrap().payload()),
        )
        .await
        .unwrap();

    let request_key = payload.get_transaction_request_key(0)?;

    let spv = client.get_spv(0, request_key).await?;

    spv.verify(&HashValue::new(
        *target_block
            .chain_headers()
            .first()
            .expect("Should have a header root")
            .hash(),
    ))?;*/

    Ok(())
}

async fn initialize_light_client(
    proving_mode: Arc<ProvingMode>,
    chainweb_node_address: Arc<String>,
    proof_server_address: Arc<String>,
) -> Result<(Client, Box<LightClientState>, VerifierState)> {
    let client = Client::new(
        chainweb_node_address.as_str(),
        proof_server_address.as_str(),
    );

    info!("Fetching data to prove longest chain with target block height {CHECKPOINT_BLOCK_HEIGHT} and block window {BLOCK_WINDOW}");

    let layer_headers = client
        .get_layer_block_headers(CHECKPOINT_BLOCK_HEIGHT, BLOCK_WINDOW)
        .await?;

    info!("Starting proving process for the longest chain");

    let proof = client
        .prove_longest_chain(*proving_mode, layer_headers.clone())
        .await?;

    info!("Proof generated, verifying it...");

    let is_valid = client.verify_longest_chain(proof).await?;

    if !is_valid {
        return Err(anyhow!("Proof of longest chain is not valid"));
    }

    info!("Proof of longest chain is valid");

    let lc_state = LightClientState::default();

    let mut validated_layer_hash = [HashValue::default(); VERIFIER_STORED_CHECKPOINT_COUNT];

    validated_layer_hash[0] = layer_headers
        .get(layer_headers.len() / 2)
        .expect("Should have a first header")
        .header_root()
        .expect("Should have a header root");

    let verifier_state = VerifierState {
        validated_layer_hash,
        confirmation_work_threshold: U256::from(CONFIRMATION_WORK_THRESHOLD),
    };

    Ok((client, Box::new(lc_state), verifier_state))
}

/// This method creates a listener for new tasks to verify proofs and processes them.
///
/// # Arguments
///
/// * `task_receiver` - The receiver channel for the tasks.
/// * `initial_verifier_state` - The initial verifier state.
/// * `client` - The client.
/// * `store` - The store.

async fn verifier_task(
    task_sender: Arc<mpsc::Sender<VerificationTask>>,
    mut task_receiver: mpsc::Receiver<VerificationTask>,
    initial_verifier_state: VerifierState,
    client: Arc<Client>,
    lc_state: Arc<RwLock<Box<LightClientState>>>,
) {
    let mut verifier_state = initial_verifier_state;

    // Interval to continue processing tasks when one has been recycled.
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    // Start as one to not rewrite the initial state.
    let mut rotating_index = 1;

    while let Some(proof_type) = task_receiver.recv().await {
        info!("Received a new task to verify: {}", &proof_type);

        // If task is not complete we send it back in the queue. This
        // allows us to continue receiving inclusion verification task
        // while the sync committee one is not done.
        if !proof_type.task_finished() {
            info!("Task is not finished, send back to the queue...");
            let send_res = task_sender.send(proof_type).await;

            if let Err(e) = send_res {
                error!("Failed to recycle task to the verifier: {:?}", e);
            }

            interval.tick().await;

            continue;
        }

        match proof_type {
            VerificationTask::LongestChain { task, permit } => {
                // Wait for the task to finish and handle the result.
                match task.await {
                    Ok(result) => match result {
                        Ok(proof) => {
                            info!("Start verifying longest chain proof");
                            let res = client.verify_longest_chain(proof.clone()).await;

                            if let Ok(true) = res {
                                info!("Proof of longest chain verified successfully");
                                let outputs = LongestChainOut::from(&mut proof.public_values());

                                if !verifier_state
                                    .validated_layer_hash
                                    .contains(&outputs.first_layer_block_header_hash())
                                {
                                    error!("First layer block header hash is not known by the verifier");
                                    drop(permit);

                                    continue;
                                }
                                info!(
                                        "Base layer block header hash matches one known by the verifier"
                                    );

                                if !outputs.confirmation_work()
                                    >= verifier_state.confirmation_work_threshold
                                {
                                    error!("Confirmation work is not greater than the cumulative work threshold");
                                    drop(permit);

                                    continue;
                                }
                                info!(
                                        "Confirmation work is greater than the cumulative work threshold"
                                    );

                                // TODO update client state to new block height
                                verifier_state.validated_layer_hash[rotating_index] =
                                    outputs.target_layer_block_header_hash();
                                rotating_index =
                                    (rotating_index + 1) % VERIFIER_STORED_CHECKPOINT_COUNT;

                                drop(permit);
                            } else {
                                error!("Longest chain proof verification failed: {:?}", res);
                            }
                        }
                        Err(e) => {
                            eprintln!("Task failed: {:?}", e);
                        }
                    },
                    Err(e) => {
                        // The task was cancelled.
                        eprintln!("Task was cancelled: {:?}", e);
                    }
                }
            }
            VerificationTask::Spv { task, permit } => {
                // Wait for the task to finish and handle the result.
                match task.await {
                    Ok(result) => match result {
                        Ok((boxed_spv, proof)) => {
                            info!("Start verifying SPV proof");
                            let res = client.verify_spv(proof.clone()).await;

                            if let Ok(true) = res {
                                info!("Proof of SPV verified successfully");
                                let outputs = SpvOut::from(&mut proof.public_values());

                                if !verifier_state
                                    .validated_layer_hash
                                    .contains(&outputs.first_layer_block_header_hash())
                                {
                                    error!("First layer block header hash is not known by the verifier");
                                    drop(permit);

                                    continue;
                                }
                                info!(
                                        "Base layer block header hash matches one known by the verifier"
                                    );

                                if !outputs.confirmation_work()
                                    >= verifier_state.confirmation_work_threshold
                                {
                                    error!("Confirmation work is not greater than the cumulative work threshold");
                                    drop(permit);

                                    continue;
                                }
                                info!(
                                        "Confirmation work is greater than the cumulative work threshold"
                                    );

                                if boxed_spv
                                    .subject()
                                    .hash_as_leaf()
                                    .expect("Should be able to hash the subject of the proof")
                                    != *outputs.subject_hash()
                                {
                                    error!("Hash of the subject is not the same as the one in the proof");
                                    drop(permit);

                                    continue;
                                }
                                info!("Hash of the subject is the same as the one in the proof");

                                // TODO update client state to new block height
                                verifier_state.validated_layer_hash[rotating_index] =
                                    *outputs.target_layer_block_header_hash();
                                rotating_index = (rotating_index + 1) % 4;

                                drop(permit);
                            } else {
                                error!("SPV proof verification failed: {:?}", res);
                            }
                        }
                        Err(e) => {
                            eprintln!("Task failed: {:?}", e);
                        }
                    },
                    Err(e) => {
                        // The task was cancelled.
                        eprintln!("Task was cancelled: {:?}", e);
                    }
                }
            }
        }
    }
}
