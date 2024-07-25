// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use ethereum_lc::client::error::ClientError;
use ethereum_lc::client::Client;
use ethereum_lc::proofs::committee_change::CommitteeChangeOut;
use ethereum_lc::proofs::inclusion::StorageInclusionOut;
use ethereum_lc::proofs::{ProofType, ProvingMode};
use ethereum_lc_core::crypto::hash::HashValue;
use ethereum_lc_core::merkle::storage_proofs::EIP1186Proof;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::Update;
use ethereum_lc_core::types::utils::calc_sync_period;
use log::{debug, error, info};
use std::env;
use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinHandle;

/// The maximum number of light client updates that can be requested.
///
/// From [the Altair specifications](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration).
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u8 = 128;

/// Address for which we fetch the proof of storage.
/// From [the Uniswap v2 documentation](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/v2-deployments).
pub const UNISWAP_V2_ADDRESS: &str = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";

/// Storage key corresponding to [the `allPairs` mapping](https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Factory.sol#L11) in the Uniswap v2 contract.
/// Calculated with `keccak256(abi.encodePacked(uint256(2)))`.
pub const ALL_PAIRS_STORAGE_KEY: &str =
    "0x290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba";

/// The CLI for the light client.
#[derive(Parser)]
struct Cli {
    /// The address of the checkpoint service provider.
    ///
    /// See https://eth-clients.github.io/checkpoint-sync-endpoints
    #[arg(short, long)]
    checkpoint_provider_address: String,

    /// The address for the beacon node API.
    ///
    /// It is recommended to use https://www.lightclientdata.org
    #[arg(short, long)]
    beacon_node_address: String,

    /// The address of the proof server
    #[arg(short, long)]
    proof_server_address: String,

    /// The address of the RPC provider
    #[arg(short, long)]
    rpc_provider_address: String,
}

#[derive(Debug, Clone)]
pub struct VerifierState {
    current_sync_committee: HashValue,
    next_sync_committee: HashValue,
}

pub enum VerificationTask {
    CommitteeChange {
        task: JoinHandle<Result<(Update, ProofType), ClientError>>,
        permit: OwnedSemaphorePermit,
    },
    StorageInclusion {
        task: JoinHandle<Result<(Update, ProofType), ClientError>>,
        permit: OwnedSemaphorePermit,
    },
}

impl Display for &VerificationTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationTask::CommitteeChange { .. } => write!(f, "Sync Committee Change"),
            VerificationTask::StorageInclusion { .. } => write!(f, "Storage Inclusion"),
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
        checkpoint_provider_address,
        beacon_node_address,
        proof_server_address,
        rpc_provider_address,
        ..
    } = Cli::parse();

    // Initialize the logger.
    env_logger::init();

    let checkpoint_provider_address = Arc::new(checkpoint_provider_address);
    let beacon_node_address = Arc::new(beacon_node_address);
    let proof_server_address = Arc::new(proof_server_address);
    let rpc_provider_address = Arc::new(rpc_provider_address);

    // Initialize the Light Client.
    let (client, store, verifier_state) = initialize_light_client(
        mode.clone(),
        checkpoint_provider_address,
        beacon_node_address,
        proof_server_address,
        rpc_provider_address,
    )
    .await
    .expect("Failed to initialize light client");

    let store = Arc::new(RwLock::new(store));
    let client = Arc::new(client);

    info!("Light client initialized successfully");

    // Create a Semaphore with only one permit for the proofs process.
    let inclusion_semaphore = Arc::new(Semaphore::new(1));
    let committee_change_semaphore = Arc::new(Semaphore::new(1));

    info!("Spawn verifier task");
    let (task_sender, task_receiver) = mpsc::channel::<VerificationTask>(100);

    // Start the main loop to listen for Eth data every 10 seconds.
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    // Spawn a verifier task that sequentially processes the tasks.
    tokio::spawn(verifier_task(
        task_receiver,
        verifier_state,
        client.clone(),
        store.clone(),
    ));

    debug!("Start listening for Eth data");

    loop {
        interval.tick().await;

        if inclusion_semaphore.available_permits() > 0 {
            info!("Starting process to prove storage inclusion...");
            // Acquire a permit from the semaphore before starting the inclusion task.
            let permit = inclusion_semaphore.clone().acquire_owned().await?;

            info!("Fetching proof of storage inclusion for the latest block...");
            // Fetch latest finality update.
            let finality_update = client
                .get_finality_update()
                .await
                .expect("Failed to fetch finality update");

            info!("Fetching EIP1186 proof...");
            // Fetch EIP1186 proof.
            let inclusion_merkle_proof = client
                .get_proof(
                    UNISWAP_V2_ADDRESS,
                    &[String::from(ALL_PAIRS_STORAGE_KEY)],
                    &format!(
                        "0x{}",
                        hex::encode(
                            finality_update
                                .finalized_header()
                                .execution()
                                .block_hash()
                                .as_ref()
                        )
                    ),
                )
                .await
                .expect("Failed to fetch storage inclusion proof");

            let light_client_internal = EIP1186Proof::try_from(inclusion_merkle_proof)
                .expect("Failed to convert to EIP1186Proof");

            info!("Generating proof of inclusion...");

            let mode_clone = mode.clone();
            let store_clone = store.clone();
            let client_clone = client.clone();

            // Spawn proving task for inclusion proof, and send it to the verifier task.
            let task = tokio::spawn(async move {
                let store = store_clone.read().await;
                let update = Update::from(finality_update);
                let proof = client_clone
                    .prove_storage_inclusion(mode_clone, &store, &update, &light_client_internal)
                    .await?;
                drop(store);
                info!("Proof of storage inclusion generated successfully");

                Ok((update, proof))
            });

            task_sender
                .send(VerificationTask::StorageInclusion { task, permit })
                .await?;
        }

        info!("Looking for potential update....");

        let potential_update = check_update(client.clone(), store.clone()).await?;

        if potential_update.is_some() && committee_change_semaphore.available_permits() > 0 {
            // Acquire a permit from the semaphore before starting the committee change task.
            let permit = committee_change_semaphore.clone().acquire_owned().await?;

            let mode_clone = mode.clone();
            let store_clone = store.clone();
            let client_clone = client.clone();

            // Spawn proving task for committee change proof, and send it to the verifier task.
            let task = tokio::spawn(async move {
                let store = store_clone.read().await;
                let update = potential_update.unwrap();

                let proof = client_clone
                    .prove_committee_change(mode_clone, &store, &update)
                    .await?;
                drop(store);
                info!("Proof of committee change generated successfully");

                Ok((update, proof))
            });

            task_sender
                .send(VerificationTask::CommitteeChange { task, permit })
                .await?;
        }
    }
}

async fn initialize_light_client(
    proving_mode: ProvingMode,
    checkpoint_provider_address: Arc<String>,
    beacon_node_address: Arc<String>,
    proof_server_address: Arc<String>,
    rpc_provider_address: Arc<String>,
) -> Result<(Client, LightClientStore, VerifierState)> {
    // Instantiate client.
    let client = Client::new(
        &checkpoint_provider_address,
        &beacon_node_address,
        &proof_server_address,
        &rpc_provider_address,
    );

    info!("Fetching latest state checkpoint and bootstrap data...");

    // Fetch latest state checkpoint.
    let checkpoint = client
        .get_checkpoint(None)
        .await
        .expect("Failed to fetch checkpoint");

    let checkpoint_block_root = match checkpoint.block_root() {
        Some(block_root) => block_root,
        None => panic!("No block root found in checkpoint"),
    };

    info!("Latest checkpoint: {:?}", checkpoint_block_root);

    // Fetch bootstrap data.
    let bootstrap = client
        .get_bootstrap_data(checkpoint_block_root)
        .await
        .expect("Failed to fetch bootstrap data");

    info!(
        "Initializing Light Client store at checkpoint: {:?}",
        checkpoint_block_root
    );

    // Initialize store
    let trusted_block_root = hex::decode(
        checkpoint_block_root
            .strip_prefix("0x")
            .expect("Checkpoint should start with \"0x\""),
    )
    .expect("Failed to decode checkpoint block root")
    .try_into()
    .expect("Failed to convert checkpoint bytes to Bytes32");

    let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap)
        .expect("Could not initialize the store based on bootstrap data");

    info!("Fetching updates...");

    // Fetch updates
    let sync_period = calc_sync_period(bootstrap.header().beacon().slot());

    let update_response = client
        .get_update_data(sync_period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await
        .expect("Failed to fetch update data");

    info!(
        "Got {} updates, starting processing...",
        update_response.updates().len()
    );

    let mut verifier_state = VerifierState {
        current_sync_committee: HashValue::default(),
        next_sync_committee: HashValue::default(),
    };

    for (i, update) in update_response.updates().iter().enumerate() {
        info!(
            "Processing update at slot: {:?}",
            update.update().attested_header().beacon().slot()
        );

        if calc_sync_period(bootstrap.header().beacon().slot())
            != calc_sync_period(update.update().attested_header().beacon().slot())
        {
            info!("Sync period changed, updating store...");
        }

        let proof = client
            .prove_committee_change(proving_mode.clone(), &store, update.update())
            .await
            .expect("Failed to prove committee change");

        client
            .verify_committee_change(proof.clone())
            .await
            .expect("Failed to prove committee change");

        if i == update_response.updates().len() - 1 {
            let outputs: CommitteeChangeOut = CommitteeChangeOut::from(&mut proof.public_values());

            verifier_state.current_sync_committee = outputs.new_sync_committee();
            verifier_state.next_sync_committee = outputs.new_next_sync_committee();
        }

        // TODO this is redundant, to simplify
        store
            .process_light_client_update(update.update())
            .expect("Failed to process update");
    }

    Ok((client, store, verifier_state))
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
    mut task_receiver: mpsc::Receiver<VerificationTask>,
    initial_verifier_state: VerifierState,
    client: Arc<Client>,
    store: Arc<RwLock<LightClientStore>>,
) {
    let mut verifier_state = initial_verifier_state;
    while let Some(proof_type) = task_receiver.recv().await {
        info!("Received a new task to verify: {}", &proof_type);

        match proof_type {
            VerificationTask::CommitteeChange { task, permit } => {
                // Wait for the task to finish and handle the result.
                match task.await {
                    Ok(result) => match result {
                        Ok((update, proof)) => {
                            info!("Start verifying sync committee change proof");
                            let res = client.verify_committee_change(proof.clone()).await;

                            if let Ok(true) = res {
                                info!("Proof of sync committee change verified successfully");
                                let outputs = CommitteeChangeOut::from(&mut proof.public_values());

                                if outputs.signer_sync_committee()
                                    == verifier_state.current_sync_committee
                                {
                                    info!(
                                        "Signer sync committee matches the current sync committee"
                                    );
                                    verifier_state.current_sync_committee =
                                        outputs.new_sync_committee();
                                    verifier_state.next_sync_committee =
                                        outputs.new_next_sync_committee();

                                    let mut lock = store.blocking_write();
                                    lock.process_light_client_update(&update).unwrap();

                                    drop(permit);
                                } else {
                                    error!("Signer sync committee does not match the current sync committee");
                                }
                            } else {
                                error!("Committee change proof verification failed: {:?}", res);
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
            VerificationTask::StorageInclusion { task, permit } => {
                // Wait for the task to finish and handle the result.
                match task.await {
                    Ok(result) => match result {
                        Ok((_update, proof)) => {
                            info!("Start verifying inclusion proof");
                            let res = client.verify_storage_inclusion(proof.clone()).await;

                            if let Ok(true) = res {
                                info!("Proof of storage inclusion verified successfully");
                                let outputs = StorageInclusionOut::from(&mut proof.public_values());

                                if outputs.sync_committee_hash()
                                    == verifier_state.current_sync_committee
                                    || outputs.sync_committee_hash()
                                        == verifier_state.next_sync_committee
                                {
                                    info!("Sync committee hash matches the current or next sync committee");
                                    println!(
                                        "Sync committee hash: {:?}",
                                        verifier_state.current_sync_committee
                                    );
                                    println!(
                                        "Attested block number: {:?}",
                                        outputs.finalized_block_height()
                                    );

                                    drop(permit);
                                } else {
                                    error!("Sync committee hash does not match the current or next sync committee");
                                    continue;
                                }
                            } else {
                                error!("Storage inclusion proof verification failed: {:?}", res);
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

/// This method checks if there is a new update containing a sync committee change available.
///
/// # Arguments
///
/// * `client` - The client.
/// * `store` - The store.
///
/// # Returns
///
/// An optional update if a new update is available.
async fn check_update(
    client: Arc<Client>,
    store: Arc<RwLock<LightClientStore>>,
) -> Result<Option<Update>> {
    let store = store.read().await;
    let known_period = calc_sync_period(store.finalized_header().beacon().slot());
    let update = client
        .get_update_data(known_period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
        .await?;
    update.contains_committee_change(known_period)
}
