use aptos_lc::merkle::{SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets};
use aptos_lc_core::aptos_test_utils::wrapper::{AptosWrapper, ExecuteBlockArgs};
use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::types::trusted_state::{EpochChangeProof, TrustedState, TrustedStateChange};
use aptos_lc_core::types::validator::ValidatorVerifier;
use aptos_lc_core::NBR_VALIDATORS;
use serde::Serialize;
use std::time::Instant;
use wp1_sdk::utils::setup_logger;
use wp1_sdk::{ProverClient, SP1CoreProof, SP1Stdin};

const AVERAGE_SIGNERS_NBR: usize = 95;
const NBR_ACCOUNTS: usize = 25000;

#[derive(Serialize)]
struct Timings {
    ratchet_proving_time: u128,
    merkle_proving_time: u128,
}

fn main() {
    // Initialize assets needed for the test.
    let mut aptos_wrapper = AptosWrapper::new(NBR_ACCOUNTS, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR);

    // Get trusted state after genesis.
    let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
    let validator_verifier = match TrustedState::from_bytes(&trusted_state).unwrap() {
        TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().clone(),
        _ => panic!("expected epoch state"),
    };
    let validator_verifier_hash = validator_verifier.hash();
    let trusted_state_version = *aptos_wrapper.current_version();

    // Generate a block with transactions and set a new epoch.
    aptos_wrapper.generate_traffic();

    // Get epoch change proof for ratcheting.
    let state_proof = aptos_wrapper.new_state_proof(trusted_state_version);
    let epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

    // Instantiate prover client.
    let prover_client = ProverClient::new();

    // Out of circuit ratcheting for ensuring proper one in circuit, and also
    // for later merkle verification.
    let start_ratchet_proving = Instant::now();
    let mut public_values = prove_ratchet(
        &prover_client,
        &trusted_state,
        epoch_change_proof,
        validator_verifier_hash.as_ref(),
    );
    let ratchet_proving_time = start_ratchet_proving.elapsed();

    let validator_verifier_hash: [u8; 32] = public_values.public_values.read();

    let (validator_verifier, expected_hash) =
        verify_and_ratchet_with_hash(&trusted_state, epoch_change_proof);

    // Assert have the expected validator verifier hash.
    assert_eq!(
        &validator_verifier_hash,
        expected_hash.as_ref(),
        "Validator verifier hash mismatch with previously known one"
    );

    // Retrieve assets for merkle verification.
    aptos_wrapper.execute_block(ExecuteBlockArgs::StateProof(Box::new(state_proof)));

    aptos_wrapper.generate_traffic();

    let proof_assets = aptos_wrapper
        .get_latest_proof_account(NBR_ACCOUNTS - 1)
        .unwrap();

    let sparse_merkle_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
    let key: [u8; 32] = *proof_assets.key().as_ref();
    let element_hash: [u8; 32] = *proof_assets.state_value_hash().as_ref();

    let transaction = bcs::to_bytes(&proof_assets.transaction()).unwrap();
    let transaction_proof = bcs::to_bytes(&proof_assets.transaction_proof()).unwrap();
    let latest_li = aptos_wrapper.get_latest_li_bytes().unwrap();

    let sparse_merkle_proof_assets =
        SparseMerkleProofAssets::new(sparse_merkle_proof, key, element_hash);

    let transaction_proof_assets = TransactionProofAssets::new(
        transaction,
        *proof_assets.transaction_version(),
        transaction_proof,
        latest_li,
    );

    let validator_verifier_assets =
        ValidatorVerifierAssets::new(validator_verifier.to_bytes(), validator_verifier_hash);

    let start_merkle_proving = Instant::now();
    let mut public_values = prove_merkle(
        &prover_client,
        &sparse_merkle_proof_assets,
        &transaction_proof_assets,
        &validator_verifier_assets,
    );
    let merkle_proving_time = start_merkle_proving.elapsed();
    let merkle_root_slice: [u8; 32] = public_values.public_values.read();

    assert_eq!(
        &merkle_root_slice,
        proof_assets
            .transaction()
            .ensure_state_checkpoint_hash()
            .unwrap()
            .as_ref(),
        "Merkle root hash mismatch"
    );

    // Output timings.
    let timings = Timings {
        ratchet_proving_time: ratchet_proving_time.as_millis(),
        merkle_proving_time: merkle_proving_time.as_millis(),
    };

    let json_output = serde_json::to_string(&timings).unwrap();
    println!("{}", json_output);
}

fn prove_ratchet(
    client: &ProverClient,
    trusted_state: &[u8],
    epoch_change_proof: &[u8],
    trusted_state_hash: &[u8],
) -> SP1CoreProof {
    let mut stdin = SP1Stdin::new();

    setup_logger();

    stdin.write(&trusted_state);
    stdin.write(&epoch_change_proof);
    stdin.write(&trusted_state_hash);

    client
        .prove(aptos_programs::RATCHET_PROGRAM, &stdin)
        .unwrap()
}

fn prove_merkle(
    client: &ProverClient,
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> SP1CoreProof {
    let mut stdin = SP1Stdin::new();

    setup_logger();

    // Account inclusion input
    stdin.write(sparse_merkle_proof_assets.sparse_merkle_proof());
    stdin.write(sparse_merkle_proof_assets.leaf_key());
    stdin.write(sparse_merkle_proof_assets.leaf_hash());

    // Tx inclusion input
    stdin.write(transaction_proof_assets.transaction());
    stdin.write(transaction_proof_assets.transaction_index());
    stdin.write(transaction_proof_assets.transaction_proof());
    stdin.write(transaction_proof_assets.latest_li());

    // Validator verifier
    stdin.write(validator_verifier_assets.validator_verifier());
    stdin.write(validator_verifier_assets.validator_hash());

    client
        .prove(aptos_programs::MERKLE_PROGRAM, &stdin)
        .unwrap()
}

fn verify_and_ratchet_with_hash(
    trusted_state: &[u8],
    epoch_change_proof: &[u8],
) -> (ValidatorVerifier, HashValue) {
    let trusted_state = TrustedState::from_bytes(trusted_state).unwrap();
    let epoch_change_proof = EpochChangeProof::from_bytes(epoch_change_proof)
        .expect("EpochChangeProof::from_bytes: could not create epoch change proof");

    let trusted_state_change = trusted_state
        .verify_and_ratchet_inner(&epoch_change_proof)
        .expect("TrustedState::verify_and_ratchet: could not verify and ratchet trusted state");

    match trusted_state_change {
        TrustedStateChange::Epoch {
            latest_epoch_change_li,
            ..
        } => {
            let validator_verifier = latest_epoch_change_li
                .ledger_info()
                .next_epoch_state()
                .expect("Expected epoch state")
                .verifier();

            (validator_verifier.clone(), validator_verifier.hash())
        }
        _ => panic!("Expected epoch change"),
    }
}
