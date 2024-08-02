// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Client
//!
//! The Client is a piece of software that serves as a coordinator between an Aptos Public Full Node
//! and the Proof Server. It is responsible for fetching data from the Aptos node and sending it to
//! the Proof Server to generate and verify proofs.
//!
//! In its current implementation, the client is also responsible for mocking a verifier state that
//! would otherwise be a blockchian, such as Ethereum.
//!
//! ## Design
//!
//! The client has two main phases in its lifetime:
//! - **Initialization**: In this phase, the client fetches the initial data from the Aptos node and
//!   generates the initial state for itself and the verifier.
//! - **Main Loop**: In this phase, the client listens for new data from the Aptos node and generates
//!   proofs for the verifier to verify.
//!
//! ## Usage
//!
//! For a detailed usage guide, please refer to the dedicated README in `aptos/docs/src/run/setup_client.md`.
//!
//! ## Note
//!
//! When running our Client two types of proofs are generated:
//! - **Epoch Change Proof**: This proof is generated when the epoch changes in the Aptos node.
//! - **Inclusion Proof**: This proof is generated when an account is included in the ledger.
//!
//! The client is responsible for verifying these proofs and updating the verifier state accordingly.
//! The worst-case scenario that can happen in the client is that we receive the need to generate both
//! proofs at the same time. In this case, the client will send both requests to the proof server, that
//! is charged with parallelizing the proof generation, effectively reducing the time it takes to generate
//! both proofs by two.

use anyhow::{anyhow, Result};
use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::types::trusted_state::TrustedState;
use aptos_lc_core::types::waypoint::Waypoint;
use clap::Parser;
use log::{debug, error, info};
use proof_server::error::ClientError;
use proof_server::types::aptos::{
    AccountInclusionProofResponse, EpochChangeProofResponse, LedgerInfoResponse,
};
use proof_server::utils::validate_and_format_url;
use proof_server::{
    aptos_inclusion_proof_endpoint,
    types::proof_server::Request,
    utils::{read_bytes, write_bytes},
    APTOS_EPOCH_CHANGE_PROOF_ENDPOINT, APTOS_LEDGER_INFO_ENDPOINT,
};
use sphinx_sdk::SphinxProof;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

/// Address that will be used to generate the inclusion proof.
const ACCOUNT: &str = "0x2d91309b5b07a8be428ccd75d0443e81542ffcd059d0ab380cefc552229b1a";

/// A client displaying how one can make requests to the proof server and
/// handle its responses.
///
/// It can request proof generation and verification for inclusions and epoch
/// changes using data from an Aptos node.
#[derive(Parser)]
struct Cli {
    /// The address of the proof server.
    #[arg(short, long)]
    proof_server_address: String,

    /// The URL of the Aptos node.
    #[arg(short, long)]
    aptos_node_url: String,
}

/// `ClientState` is a structure meant to hold the state maintained by
/// the client. The state is a HashValue representing
/// the latest verified committee hash from the chain.
type ClientState = TrustedState;

/// Mock a verifier state. A verifier state is expected
/// to contain the latest verified committee hash.
type VerifierState = (HashValue, HashValue);

/// The type of proof that is currently being processed.
enum ProofType {
    EpochChange {
        task: JoinHandle<Result<(TrustedState, HashValue, SphinxProof), ClientError>>,
        permit: OwnedSemaphorePermit,
    },
    Inclusion {
        task: JoinHandle<Result<SphinxProof, ClientError>>,
        permit: OwnedSemaphorePermit,
    },
}

impl Display for &ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofType::EpochChange { .. } => write!(f, "Epoch Change"),
            ProofType::Inclusion { .. } => write!(f, "Inclusion"),
        }
    }
}

/// The main function of the client. It initializes the client and starts the main loop.
#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        proof_server_address,
        aptos_node_url,
        ..
    } = Cli::parse();

    // Initialize the logger
    env_logger::init();

    debug!("Validating and formatting URLs");
    // Validate and format the URLs
    let _ = validate_and_format_url(&format!("http://{}", proof_server_address))
        .map_err(|_| anyhow!("Invalid proof server URL"))?;
    let aptos_node_url =
        validate_and_format_url(&aptos_node_url).map_err(|_| anyhow!("Invalid Aptos node URL"))?;

    let proof_server_address = Arc::new(proof_server_address);
    let aptos_node_url = Arc::new(aptos_node_url);

    debug!("Initializing client");
    // Initialize the client.
    let (client_state, verififer_state) = init(&proof_server_address, &aptos_node_url).await?;
    debug!("Client initialized successfully");

    let client_state: Arc<Mutex<ClientState>> = Arc::new(Mutex::new(client_state));

    // Create a Semaphore with only one permit for the proofs process.
    let inclusion_semaphore = Arc::new(Semaphore::new(1));
    let epoch_change_semaphore = Arc::new(Semaphore::new(1));

    debug!("Spawn verifier task");
    let (task_sender, task_receiver) = mpsc::channel::<ProofType>(100);

    // Spawn a verifier task that sequentially processes the tasks.
    tokio::spawn(verifier_task(
        task_receiver,
        proof_server_address.clone(),
        verififer_state,
        client_state.clone(),
    ));

    // Start the main loop to listen for Aptos data every 10 seconds.
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    debug!("Start listening for Aptos data");
    loop {
        interval.tick().await;

        let ledger_info_request = format!("{}{APTOS_LEDGER_INFO_ENDPOINT}", aptos_node_url);
        let ledger_info: LedgerInfoResponse =
            bcs::from_bytes(&request_aptos_node(&ledger_info_request).await?).map_err(|err| {
                ClientError::ResponsePayload {
                    endpoint: ledger_info_request,
                    source: err.into(),
                }
            })?;

        let aptos_epoch = u64::from_str(&ledger_info.epoch())
            .map_err(|err| ClientError::Internal { source: err.into() })?;

        let client_state_epoch = {
            let client_state = client_state.lock().await;
            client_state.epoch().ok_or_else(|| ClientError::Internal {
                source: "ClientState ended up with a TrustedState without an epoch".into(),
            })?
        };

        // Check if epoch changed and ig the epoch changed semaphore has a permit available.
        if aptos_epoch != client_state_epoch && epoch_change_semaphore.available_permits() > 0 {
            // Acquire a permit from the semaphore before starting the inclusion task.
            let permit = epoch_change_semaphore
                .clone()
                .acquire_owned()
                .await
                .unwrap();

            // Spawn proving task for epoch change proof, and send it to the verifier task.
            let task = tokio::spawn(epoch_change_proving_task(
                proof_server_address.clone(),
                aptos_node_url.clone(),
                aptos_epoch,
            ));
            task_sender
                .send(ProofType::EpochChange { task, permit })
                .await
                .map_err(|err| ClientError::Internal {
                    source: format!(
                        "Failed to send an Epoch Change in the task channel: {}",
                        err
                    )
                    .into(),
                })?;
        }

        // Check if the inclusion semaphore has a permit available.
        if inclusion_semaphore.available_permits() > 0 {
            // Acquire a permit from the semaphore before starting the inclusion task.
            let permit = inclusion_semaphore.clone().acquire_owned().await.unwrap();

            // Spawn proving task for inclusion proof.
            let task = tokio::spawn(inclusion_proving_task(
                proof_server_address.clone(),
                aptos_node_url.clone(),
                ACCOUNT.into(),
            ));

            // Send the task and the permit to the verifier.
            task_sender
                .send(ProofType::Inclusion { task, permit })
                .await
                .unwrap();
        }
    }
}

/// Method to initialize the client. It fetches the initial data from the Aptos node and generates
/// the initial state for the client and the verifier. While initializing the client, it handles the
/// generation of both proof as it would happen in the worst-case scenario.
///
/// # Arguments
///
/// * `proof_server_address` - The address of the proof server.
/// * `aptos_node_url` - The URL of the Aptos node.
///
/// # Returns
///
/// A tuple containing the client state and the verifier state.
async fn init(
    proof_server_address: &Arc<String>,
    aptos_node_url: &Arc<String>,
) -> Result<(ClientState, VerifierState), ClientError> {
    info!("Initializing client");

    let ledger_info_request = format!("{}{APTOS_LEDGER_INFO_ENDPOINT}", aptos_node_url);
    let ledger_info: LedgerInfoResponse =
        bcs::from_bytes(&request_aptos_node(&ledger_info_request).await?).map_err(|err| {
            ClientError::ResponsePayload {
                endpoint: ledger_info_request,
                source: err.into(),
            }
        })?;

    // Spawn epoch change proving task and inclusion proving task.
    let epoch_change_task = tokio::spawn(epoch_change_proving_task(
        proof_server_address.clone(),
        aptos_node_url.clone(),
        u64::from_str(&ledger_info.epoch())
            .map_err(|err| ClientError::Internal { source: err.into() })?,
    ));

    let inclusion_task = tokio::spawn(inclusion_proving_task(
        proof_server_address.clone(),
        aptos_node_url.clone(),
        ACCOUNT.into(),
    ));

    // Await for both tasks to end.
    let (epoch_change_payload, inclusion_payload) =
        tokio::try_join!(epoch_change_task, inclusion_task,)
            .map_err(|err| ClientError::Join { source: err })?;

    // Verify epoch change proof.
    let (ratcheted_trusted_state, validator_verifier_hash, mut epoch_change_proof) =
        epoch_change_payload?;
    let mut inclusion_proof = inclusion_payload?;

    let verifier_state = (validator_verifier_hash, HashValue::default());

    let verifier_state = epoch_change_verifying_task(
        proof_server_address.clone(),
        &mut epoch_change_proof,
        verifier_state,
    )
    .await?;

    // Verify inclusion proof.
    let verifier_state = inclusion_verifying_task(
        proof_server_address.clone(),
        &mut inclusion_proof,
        verifier_state,
    )
    .await?;

    Ok((ratcheted_trusted_state, verifier_state))
}

/// This method calls the endpoint to fetch epoch change proof data from the Aptos node and returns
/// the deserialized payload.
///
/// # Arguments
///
/// * `aptos_node_url` - The URL of the Aptos node.
/// * `specific_epoch` - The specific epoch to fetch the epoch change proof data. Latest one if none
///   specified.
///
/// # Returns
///
/// The deserialized payload of the epoch change proof data.
async fn fetch_epoch_change_proof_data(
    aptos_node_url: &str,
    specific_epoch: Option<u64>,
) -> Result<EpochChangeProofResponse, ClientError> {
    let mut request_address = format!("{}{APTOS_EPOCH_CHANGE_PROOF_ENDPOINT}", aptos_node_url);

    if let Some(epoch_number) = specific_epoch {
        request_address = format!("{}?epoch_number={}", request_address, epoch_number);
    }

    bcs::from_bytes(&request_aptos_node(&request_address).await?).map_err(|err| {
        ClientError::ResponsePayload {
            endpoint: request_address,
            source: err.into(),
        }
    })
}

/// This method calls the endpoint to fetch epoch change proof data from the Aptos node and returns
/// the deserialized payload.
///
/// # Arguments
///
/// * `aptos_node_url` - The URL of the Aptos node.
///
/// # Returns
///
/// The deserialized payload of the epoch change proof data.
async fn fetch_inclusion_proof_data(
    aptos_node_url: &str,
) -> Result<AccountInclusionProofResponse, ClientError> {
    let request_address = format!(
        "{}{}",
        aptos_node_url,
        aptos_inclusion_proof_endpoint(ACCOUNT)
    );

    bcs::from_bytes(&request_aptos_node(&request_address).await?).map_err(|err| {
        ClientError::ResponsePayload {
            endpoint: request_address,
            source: err.into(),
        }
    })
}

/// This method sends a request to the Aptos node and returns the deserialized payload.
/// It is a generic method that can be used to fetch any data from the Aptos node.
///
/// # Arguments
///
/// * `request_url` - The URL of the Aptos node.
///
/// # Returns
///
/// The payload of the response as bytes.
///
/// # Errors
///
/// This method returns an error if the request fails or if the response payload
/// can't be deserialized.
async fn request_aptos_node(request_url: &str) -> Result<Vec<u8>, ClientError> {
    info!("Requesting data from Aptos node: {}", request_url);

    let client = reqwest::Client::new();

    let response = client
        .get(request_url)
        .header("Accept", "application/x-bcs")
        .send()
        .await
        .map_err(|err| ClientError::Request {
            endpoint: request_url.into(),
            source: err.into(),
        })?;

    let response_bytes = response
        .bytes()
        .await
        .map_err(|err| ClientError::Internal { source: err.into() })?;

    Ok(response_bytes.to_vec())
}

/// This method sends a request to the prover and returns the proof.
///
/// # Arguments
///
/// * `proof_server_address` - The address of the proof server.
/// * `request` - The request to send to the prover.
///
/// # Returns
///
/// The proof as bytes.
///
/// # Errors
///
/// This method returns an error if the request fails or if the response payload
/// can't be deserialized.
async fn request_prover(
    proof_server_address: &str,
    request: &Request,
) -> Result<Vec<u8>, ClientError> {
    debug!("Connecting to the proof server at {}", proof_server_address);
    let mut stream = TcpStream::connect(&proof_server_address)
        .await
        .map_err(|err| ClientError::Internal {
            source: format!("Error while connecting to proof server: {err}").into(),
        })?;
    debug!("Successfully connected to the proof server");

    info!("Sending request to prover: {}", request);

    let request_bytes =
        bcs::to_bytes(request).map_err(|err| ClientError::Internal { source: err.into() })?;

    write_bytes(&mut stream, &request_bytes)
        .await
        .map_err(|err| ClientError::Request {
            endpoint: "prover".into(),
            source: err.into(),
        })?;

    read_bytes(&mut stream)
        .await
        .map_err(|err| ClientError::Internal { source: err.into() })
}

/// This method verifies the validator verifier predicate, ie: that the validator committee that
///signed the block header corresponds to the one we have in state.
///
/// # Arguments
///
/// * `proof` - The proof to verify.
/// * `expected_hash` - The expected hash of the validator verifier.
///
/// # Returns
///
/// An error if the predicate is not satisfied.
fn assert_validator_verifier_predicate(
    proof: &mut SphinxProof,
    expected_hash: HashValue,
) -> Result<(), ClientError> {
    info!("Verifying validator verifier equality");

    let verifier_hash_slice: [u8; 32] = proof.public_values.read();
    let verifier_hash = HashValue::from_slice(verifier_hash_slice)
        .map_err(|err| ClientError::Internal { source: err.into() })?;

    if verifier_hash != expected_hash {
        return Err(ClientError::VerifierHashInequality {
            expected: expected_hash,
            actual: verifier_hash,
        });
    }

    Ok(())
}

/// This method sends a request to the prover to generate an epoch change proof.
///
/// # Arguments
///
/// * `proof_server_address` - The address of the proof server.
/// * `aptos_node_url` - The URL of the Aptos node.
/// * `epoch` - The epoch for which to generate the epoch change proof.
///
/// # Errors
///
/// This method returns an error if the request fails or if the response payload
/// can't be deserialized.
async fn epoch_change_proving_task(
    proof_server_address: Arc<String>,
    aptos_node_url: Arc<String>,
    epoch: u64,
) -> Result<(TrustedState, HashValue, SphinxProof), ClientError> {
    info!("Starting epoch change proving task for epoch: {}", epoch);

    debug!("Fetching epoch change proof data for epoch: {}", epoch);
    let epoch_change_proof_data =
        fetch_epoch_change_proof_data(&aptos_node_url, Some(epoch)).await?;

    // Retrieve the validator verifier hash for penultimate epoch.
    let validator_verifier_hash = match epoch_change_proof_data.trusted_state() {
        TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash(),
        _ => {
            return Err(ClientError::Internal {
                source: "Expected epoch state".into(),
            })
        }
    };

    debug!(
        "Got data for epoch change with penultimate committee hash: {:?}",
        validator_verifier_hash
    );

    // Request a proof generation for  the latest epoch change.
    debug!("Sending epoch change proof request to the prover");

    let request = Request::ProveEpochChange(epoch_change_proof_data.clone().into());

    let epoch_change_proof: SphinxProof = bcs::from_bytes(
        &request_prover(&proof_server_address, &request).await?,
    )
    .map_err(|err| ClientError::ResponsePayload {
        endpoint: format!("{}", &request),
        source: err.into(),
    })?;

    debug!("Epoch change proof for latest epoch received from prover");

    // Proving is done, ratchet the client state to the new trusted state.
    let ledger_info = epoch_change_proof_data
        .epoch_change_proof()
        .ledger_info_with_sigs
        .first()
        .ok_or_else(|| ClientError::Internal {
            source: "Epoch Change Proof has more than one LedgerInfoWithSignatures".into(),
        })?
        .ledger_info()
        .clone();

    let ratcheted_state = TrustedState::EpochState {
        waypoint: Waypoint::new_any(&ledger_info),
        epoch_state: ledger_info
            .next_epoch_state()
            .ok_or_else(|| ClientError::Internal {
                source: "LedgerInfoWithSignatures in EpochChangeProof has no next EpochState"
                    .into(),
            })?
            .clone(),
    };

    Ok((ratcheted_state, validator_verifier_hash, epoch_change_proof))
}

/// This method sends a request to the prover to verify an epoch change proof.
///
/// # Arguments
///
/// * `proof_server_address` - The address of the proof server.
/// * `epoch_change_proof` - The epoch change proof to verify.
/// * `verifier_state` - The verifier state to verify.
///
/// # Returns
///
/// The verifier state after the verification.
async fn epoch_change_verifying_task(
    proof_server_address: Arc<String>,
    epoch_change_proof: &mut SphinxProof,
    verifier_state: VerifierState,
) -> Result<VerifierState, ClientError> {
    info!("Starting epoch change verification task");
    // Verifying the received epoch change proof and the validator verifier hash.
    let request = Request::VerifyEpochChange(epoch_change_proof.clone());
    let epoch_change_proof_verified = *request_prover(&proof_server_address, &request)
        .await?
        .first()
        .ok_or_else(|| ClientError::ResponsePayload {
            endpoint: format!("{}", &request),
            source: "No response from prover".into(),
        })?;

    if epoch_change_proof_verified != 1 {
        return Err(ClientError::Verification(String::from(
            "Epoch Change Proof",
        )));
    }

    assert_validator_verifier_predicate(epoch_change_proof, verifier_state.0)?;

    let new_validator_hash_slice = epoch_change_proof.public_values.read::<[u8; 32]>();

    Ok((
        HashValue::from_slice(new_validator_hash_slice)
            .map_err(|err| ClientError::Internal { source: err.into() })?,
        verifier_state.1,
    ))
}

/// This method sends a request to the prover to generate an account inclusion proof.
///
/// # Arguments
///
/// * `proof_server_address` - The address of the proof server.
/// * `aptos_node_url` - The URL of the Aptos node.
/// * `account` - The account to generate the inclusion proof.
///
/// # Returns
///
/// The account inclusion proof.
async fn inclusion_proving_task(
    proof_server_address: Arc<String>,
    aptos_node_url: Arc<String>,
    account: String,
) -> Result<SphinxProof, ClientError> {
    info!("Starting account inclusion proving task");

    debug!("Fetching account inclusion proof for account: {}", account);

    let inclusion_proof_data = fetch_inclusion_proof_data(&aptos_node_url).await?;

    debug!("Sending account inclusion proof request to the prover");
    let request = Request::ProveInclusion(inclusion_proof_data.into());
    let account_inclusion_proof: SphinxProof = bcs::from_bytes(
        &request_prover(&proof_server_address, &request).await?,
    )
    .map_err(|err| ClientError::ResponsePayload {
        endpoint: format!("{}", &request),
        source: err.into(),
    })?;

    debug!("Account inclusion proof received from prover");

    Ok(account_inclusion_proof)
}

/// This method sends a request to the prover to verify an account inclusion proof.
///
/// # Arguments
///
/// * `proof_server_address` - The address of the proof server.
/// * `account_inclusion_proof` - The account inclusion proof to verify.
/// * `verifier_state` - The verifier state to verify.
///
/// # Returns
///
/// The verifier state after the verification.
async fn inclusion_verifying_task(
    proof_server_address: Arc<String>,
    account_inclusion_proof: &mut SphinxProof,
    verifier_state: VerifierState,
) -> Result<VerifierState, ClientError> {
    info!("Verifying account inclusion proof");
    // Verifying the received account inclusion proof and the validator verifier hash.
    let request = Request::VerifyInclusion(account_inclusion_proof.clone());
    let inclusion_proof_verified = *request_prover(&proof_server_address, &request)
        .await?
        .first()
        .ok_or_else(|| ClientError::ResponsePayload {
            endpoint: format!("{}", &request),
            source: "No response from prover".into(),
        })?;

    if inclusion_proof_verified != 1 {
        return Err(ClientError::Verification(String::from(
            "Account Inclusion Proof",
        )));
    }

    assert_validator_verifier_predicate(account_inclusion_proof, verifier_state.0)?;

    let new_state_root = account_inclusion_proof.public_values.read::<[u8; 32]>();

    Ok((
        verifier_state.0,
        HashValue::from_slice(new_state_root)
            .map_err(|err| ClientError::Internal { source: err.into() })?,
    ))
}

/// This method creates a listener for new tasks to verify proofs and processes them.
///
/// # Arguments
///
/// * `task_receiver` - The receiver channel for the tasks.
/// * `proof_server_address` - The address of the proof server.
/// * `initial_verifier_state` - The initial verifier state.
/// * `client_state` - The client state.
async fn verifier_task(
    mut task_receiver: mpsc::Receiver<ProofType>,
    proof_server_address: Arc<String>,
    initial_verifier_state: VerifierState,
    client_state: Arc<Mutex<ClientState>>,
) {
    let mut verifier_state = initial_verifier_state;

    while let Some(proof_type) = task_receiver.recv().await {
        info!("Received a new task to verify: {}", &proof_type);

        match proof_type {
            ProofType::EpochChange { task, permit } => {
                // Wait for the task to finish and handle the result.
                match task.await {
                    Ok(result) => match result {
                        Ok((ratcheted_trusted_state, _, mut epoch_change_proof)) => {
                            debug!("Start verifying epoch change proof");
                            let res = epoch_change_verifying_task(
                                proof_server_address.clone(),
                                &mut epoch_change_proof,
                                verifier_state,
                            )
                            .await;

                            if let Ok(updated_verifier_state) = res {
                                verifier_state = updated_verifier_state;
                            } else {
                                error!("Epoch change proof verification failed: {:?}", res);
                            }

                            let mut client_state = client_state.lock().await;
                            *client_state = ratcheted_trusted_state;
                            drop(permit)
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
            ProofType::Inclusion { task, permit } => {
                // Wait for the task to finish and handle the result.
                match task.await {
                    Ok(result) => match result {
                        Ok(mut inclusion_proof) => {
                            debug!("Start verifying inclusion proof");
                            let res = inclusion_verifying_task(
                                proof_server_address.clone(),
                                &mut inclusion_proof,
                                verifier_state,
                            )
                            .await;

                            if let Ok(updated_verifier_state) = res {
                                verifier_state = updated_verifier_state;
                            } else {
                                error!("Inclusion proof verification failed: {:?}", res);
                            }

                            drop(permit)
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
