// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

//! # Benchmark Test for Aptos Light Client
//!
//! This benchmark simulates a full end-to-end test case for the Aptos Light Client, focusing on
//! verifying the efficiency and correctness of epoch transition and account inclusion proofs.
//! It leverages the `sphinx_sdk` for predicate verification to ensure that:
//!
//! - P1(n): There exists a valid block header at a specific height with a valid Merkle root.
//! - P2(n): There exists a valid transition to a new set of validators, signed off by the current validators.
//! - P3(A, V, S_h): An account's value is included within the stated Merkle root.
//!
//! P1 and P3 are verified in the inclusion program, while P2 is verified in the ratchet program.
//!
//! This test also measures the performance of these operations to identify potential bottlenecks
//! and optimize the verification process.
//!
//! For more information on the Light Client design, its programs and the predicates used in this
//! benchmark, please refer to the  [HackMD document](https://hackmd.io/@lurk-lab/HJvnlbKGR)
use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use aptos_lc_core::aptos_test_utils::wrapper::{AptosWrapper, ExecuteBlockArgs};
use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::types::trusted_state::{EpochChangeProof, TrustedState, TrustedStateChange};
use aptos_lc_core::types::validator::ValidatorVerifier;
use serde::Serialize;
use sphinx_sdk::utils::setup_logger;
use sphinx_sdk::{ProverClient, SphinxProof, SphinxStdin};
use std::time::Instant;

const NBR_VALIDATORS: usize = 130;
const AVERAGE_SIGNERS_NBR: usize = 95;
const NBR_ACCOUNTS: usize = 25000;

#[derive(Serialize)]
struct Timings {
    ratchet_proving_time: u128,
    merkle_proving_time: u128,
}

fn main() {
    // Initialize Aptos Test Wrapper with configured validators and signers.
    let mut aptos_wrapper =
        AptosWrapper::new(NBR_ACCOUNTS, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

    // Extract and serialize the trusted state after the genesis block is created.
    let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
    let validator_verifier = match TrustedState::from_bytes(&trusted_state).unwrap() {
        TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().clone(),
        _ => panic!("expected epoch state"),
    };
    let validator_verifier_hash = validator_verifier.hash();
    let trusted_state_version = *aptos_wrapper.current_version();

    // Simulate traffic to generate a new block.
    aptos_wrapper.generate_traffic().unwrap();

    // Generate a new epoch block and serialize the epoch change proof.
    let state_proof = aptos_wrapper
        .new_state_proof(trusted_state_version)
        .unwrap();
    let aptos_epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

    // Instantiate prover client.
    let prover_client = ProverClient::new();

    // Execute proof generation for epoch change.
    let start_ratchet_proving = Instant::now();
    let mut epoch_change_proof =
        prove_epoch_change(&prover_client, &trusted_state, aptos_epoch_change_proof);
    let ratchet_proving_time = start_ratchet_proving.elapsed();

    let prev_validator_verifier_hash: [u8; 32] = epoch_change_proof.public_values.read();

    // Verify that the ratchet program produces the expected validator verifier hash.
    // This verifies validator consistency required by P2.
    assert_eq!(
        &prev_validator_verifier_hash,
        validator_verifier_hash.as_ref(),
        "The output for the previous validator verifier hash is not the expected one for the Ratchet program."
    );

    let new_validator_verifier_hash: [u8; 32] = epoch_change_proof.public_values.read();

    let (validator_verifier, expected_hash) =
        verify_and_ratchet_with_hash(&trusted_state, aptos_epoch_change_proof);

    // Assert the correct validator verifier hash against out-of-circuit computation
    // after ratcheting.
    assert_eq!(
        &new_validator_verifier_hash,
        expected_hash.as_ref(),
        "Validator verifier hash mismatch with previously known one"
    );

    // Retrieve and prepare assets for merkle verification.
    let _ = aptos_wrapper.execute_block(ExecuteBlockArgs::StateProof(Box::new(state_proof)));

    // Simulate traffic to generate a new block.
    aptos_wrapper.generate_traffic().unwrap();

    let proof_assets = aptos_wrapper
        .get_latest_proof_account(NBR_ACCOUNTS - 1)
        .unwrap();

    // Serialize and prepare merkle and accumulator proofs for the transaction and its inclusion in the ledger
    let sparse_merkle_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
    let key: [u8; 32] = *proof_assets.key().as_ref();
    let element_hash: [u8; 32] = *proof_assets.state_value_hash().unwrap().as_ref();

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

    let validator_verifier_assets = ValidatorVerifierAssets::new(validator_verifier.to_bytes());

    // Execute proof generation for an account being included
    // in the state.
    // The verification of the proofs in the program ensures the
    // account inclusion required by P3.
    let start_merkle_proving = Instant::now();
    let mut inclusion_proof = prove_inclusion(
        &prover_client,
        &sparse_merkle_proof_assets,
        &transaction_proof_assets,
        &validator_verifier_assets,
    );
    let merkle_proving_time = start_merkle_proving.elapsed();
    let output_validator_hash: [u8; 32] = inclusion_proof.public_values.read();

    // Verify the consistency of the validator verifier hash post-merkle proof.
    // This verifies the validator consistency required by P1.
    assert_eq!(
        output_validator_hash,
        new_validator_verifier_hash,
        "The output for the validator verifier hash is not the expected one for the Merkle program."
    );

    let merkle_root_slice: [u8; 32] = inclusion_proof.public_values.read();

    // Verify the consistency of the final merkle root hash computed
    // by the program against the expected one.
    // This verifies P3 out-of-circuit.
    assert_eq!(
        &merkle_root_slice,
        proof_assets
            .transaction()
            .ensure_state_checkpoint_hash()
            .unwrap()
            .as_ref(),
        "Merkle root hash mismatch"
    );

    // Serialize and print the timing results for both proofs.
    let timings = Timings {
        ratchet_proving_time: ratchet_proving_time.as_millis(),
        merkle_proving_time: merkle_proving_time.as_millis(),
    };

    let json_output = serde_json::to_string(&timings).unwrap();
    println!("{}", json_output);
}

fn prove_epoch_change(
    client: &ProverClient,
    trusted_state: &[u8],
    epoch_change_proof: &[u8],
) -> SphinxProof {
    let mut stdin = SphinxStdin::new();

    setup_logger();

    stdin.write(&trusted_state);
    stdin.write(&epoch_change_proof);

    let (pk, _) = client.setup(aptos_programs::EPOCH_CHANGE_PROGRAM);
    client.prove(&pk, stdin).unwrap()
}

fn prove_inclusion(
    client: &ProverClient,
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> SphinxProof {
    let mut stdin = SphinxStdin::new();

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

    let (pk, _) = client.setup(aptos_programs::INCLUSION_PROGRAM);
    client.prove(&pk, stdin).unwrap()
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
