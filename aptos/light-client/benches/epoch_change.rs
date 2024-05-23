//! # Benchmark Test for Aptos Light Client Epoch Transition
//!
//! This benchmark evaluates the performance of the Aptos Light Client's epoch transition proof verification.
//! It measures the time taken to prove and verify an epoch change using the `ProverClient` from `wp1_sdk`.
//! The test covers:
//!
//! - Generating and proving the epoch transition proof.
//! - Verifying the proof to ensure its correctness.
//!
//! Predicates checked during the benchmark:
//! - P2(n): Verifies that there is a valid transition to a new set of validators, signed off by the current validators.
//!
//! This benchmark aims to identify potential optimizations in the proving and verification process of epoch transitions
//! within the Aptos blockchain.
use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::trusted_state::TrustedState;
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;
use wp1_sdk::utils::setup_logger;
use wp1_sdk::{ProverClient, SP1Proof, SP1Stdin};

struct ProvingAssets {
    client: ProverClient,
    trusted_state: Vec<u8>,
    validator_verifier_hash: Vec<u8>,
    epoch_change_proof: Vec<u8>,
}

const NBR_VALIDATORS: usize = 130;
const AVERAGE_SIGNERS_NBR: usize = 95;

impl ProvingAssets {
    /// Constructs a new instance of `ProvingAssets` by setting up the necessary state and proofs for the benchmark.
    fn new() -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier_hash = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash().to_vec(),
            _ => panic!("Expected epoch change for current trusted state"),
        };
        let trusted_state_version = *aptos_wrapper.current_version();

        aptos_wrapper.generate_traffic().unwrap();

        let state_proof = aptos_wrapper
            .new_state_proof(trusted_state_version)
            .unwrap();

        let epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

        let client = ProverClient::new();

        Self {
            client,
            trusted_state,
            validator_verifier_hash,
            epoch_change_proof: epoch_change_proof.clone(),
        }
    }

    fn prove(&self) -> SP1Proof {
        let mut stdin = SP1Stdin::new();

        setup_logger();

        stdin.write(&self.trusted_state);
        stdin.write(&self.epoch_change_proof);

        let (pk, _) = self.client.setup(aptos_programs::EPOCH_CHANGE_PROGRAM);
        self.client.prove(&pk, stdin).unwrap()
    }

    fn verify(&self, proof: &SP1Proof) {
        let (_, vk) = self.client.setup(aptos_programs::EPOCH_CHANGE_PROGRAM);
        self.client.verify(proof, &vk).expect("Verification failed");
    }
}

#[derive(Serialize)]
struct Timings {
    proving_time: u128,
    verifying_time: u128,
}

fn main() {
    // Initialize the proving assets and benchmark the proving process.
    let proving_assets = ProvingAssets::new();

    let start_proving = Instant::now();
    let mut epoch_change_proof = proving_assets.prove();
    let proving_time = start_proving.elapsed();

    // Verify that the computed hash matches the expected validator verifier hash.
    let prev_validator_verifier_hash = epoch_change_proof.public_values.read::<[u8; 32]>();
    // This verifies predicate consistency required by P2.
    assert_eq!(
        prev_validator_verifier_hash,
        proving_assets.validator_verifier_hash.as_slice()
    );

    // Benchmark the verification process.
    let start_verifying = Instant::now();
    proving_assets.verify(black_box(&epoch_change_proof));
    let verifying_time = start_verifying.elapsed();

    // Print results in JSON format.
    let timings = Timings {
        proving_time: proving_time.as_millis(),
        verifying_time: verifying_time.as_millis(),
    };

    let json_output = serde_json::to_string(&timings).unwrap();
    println!("{}", json_output);
}
