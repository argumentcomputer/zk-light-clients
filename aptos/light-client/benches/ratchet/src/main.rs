use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::trusted_state::TrustedState;
use aptos_lc_core::NBR_VALIDATORS;
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;
use wp1_sdk::utils::{setup_logger, BabyBearPoseidon2};
use wp1_sdk::{ProverClient, SP1ProofWithIO, SP1Stdin};

struct ProvingAssets {
    client: ProverClient,
    trusted_state: Vec<u8>,
    validator_verifier_hash: Vec<u8>,
    epoch_change_proof: Vec<u8>,
}

const AVERAGE_SIGNERS_NBR: usize = 95;

impl ProvingAssets {
    fn new() -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR);

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier_hash = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash().to_vec(),
            _ => panic!("Expected epoch change for current trusted state"),
        };
        let trusted_state_version = *aptos_wrapper.current_version();

        aptos_wrapper.generate_traffic();

        let state_proof = aptos_wrapper.new_state_proof(trusted_state_version);

        let epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

        let client = ProverClient::new();

        Self {
            client,
            trusted_state,
            validator_verifier_hash,
            epoch_change_proof: epoch_change_proof.clone(),
        }
    }

    fn prove(&self) -> SP1ProofWithIO<BabyBearPoseidon2> {
        let mut stdin = SP1Stdin::new();

        setup_logger();

        stdin.write(&self.trusted_state);
        stdin.write(&self.epoch_change_proof);
        stdin.write(&self.validator_verifier_hash);

        self.client
            .prove(aptos_programs::RATCHET_PROGRAM, stdin)
            .unwrap()
    }

    fn verify(&self, proof: &SP1ProofWithIO<BabyBearPoseidon2>) {
        self.client
            .verify(aptos_programs::RATCHET_PROGRAM, proof)
            .expect("Verification failed");
    }
}

#[derive(Serialize)]
struct Timings {
    proving_time: u128,
    verifying_time: u128,
}

fn main() {
    let proving_assets = ProvingAssets::new();

    let start_proving = Instant::now();
    let proof = proving_assets.prove();
    let proving_time = start_proving.elapsed();

    let start_verifying = Instant::now();
    proving_assets.verify(black_box(&proof));
    let verifying_time = start_verifying.elapsed();

    // Print results in JSON format.
    let timings = Timings {
        proving_time: proving_time.as_millis(),
        verifying_time: verifying_time.as_millis(),
    };

    let json_output = serde_json::to_string(&timings).unwrap();
    println!("{}", json_output);
}
