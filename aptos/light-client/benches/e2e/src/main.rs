use aptos_lc_core::aptos_test_utils::wrapper::{AptosWrapper, ExecuteBlockArgs};
use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::merkle::proof::SparseMerkleProof;
use aptos_lc_core::types::trusted_state::{EpochChangeProof, TrustedState, TrustedStateChange};
use aptos_lc_core::NBR_VALIDATORS;
use serde::Serialize;
use std::time::Instant;
use wp1_sdk::utils::{setup_logger, BabyBearPoseidon2};
use wp1_sdk::{ProverClient, SP1ProofWithIO, SP1Stdin};

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
    let validator_verifier_hash = match TrustedState::from_bytes(&trusted_state).unwrap() {
        TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash().to_vec(),
        _ => panic!("Expected epoch change for current trusted state"),
    };
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
        &validator_verifier_hash,
    );
    let ratchet_proving_time = start_ratchet_proving.elapsed();

    let validator_verifier_hash: [u8; 32] = public_values.public_values.read();

    let expected_hash = verify_and_ratchet_with_hash(&trusted_state, epoch_change_proof);

    // Assert have the expected validator verifier hash.
    assert_eq!(
        &validator_verifier_hash,
        expected_hash.as_ref(),
        "Validator verifier hash mismatch with previously known one"
    );

    // Retrieve assets for merkle verification.
    aptos_wrapper.execute_block(ExecuteBlockArgs::StateProof(Box::new(state_proof)));
    let proof_assets = aptos_wrapper
        .get_latest_proof_account(NBR_ACCOUNTS - 1)
        .unwrap();

    let sparse_merkle_proof =
        SparseMerkleProof::from_bytes(&bcs::to_bytes(proof_assets.state_proof()).unwrap()).unwrap();
    let leaf_key = proof_assets.key().to_vec();
    let aptos_expected_root = proof_assets.root_hash().to_vec();
    let leaf_value = proof_assets.state_value_hash().to_vec();

    let start_merkle_proving = Instant::now();
    let mut public_values = prove_merkle(
        &prover_client,
        &sparse_merkle_proof.to_bytes(),
        &leaf_key,
        &leaf_value,
        aptos_expected_root.as_ref(),
    );
    let merkle_proving_time = start_merkle_proving.elapsed();

    let merkle_root_slice: [u8; 32] = public_values.public_values.read();

    assert_eq!(
        merkle_root_slice.to_vec(),
        aptos_expected_root,
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
) -> SP1ProofWithIO<BabyBearPoseidon2> {
    let mut stdin = SP1Stdin::new();

    setup_logger();

    stdin.write(&trusted_state);
    stdin.write(&epoch_change_proof);
    stdin.write(&trusted_state_hash);

    client
        .prove(aptos_programs::RATCHET_PROGRAM, stdin)
        .unwrap()
}

fn prove_merkle(
    client: &ProverClient,
    sparse_merkle_proof: &[u8],
    leaf_key: &[u8],
    leaf_value: &[u8],
    expected_root: &[u8],
) -> SP1ProofWithIO<BabyBearPoseidon2> {
    let mut stdin = SP1Stdin::new();

    setup_logger();

    stdin.write(&sparse_merkle_proof);
    stdin.write(&<[u8; 32]>::try_from(leaf_key).unwrap());
    stdin.write(&<[u8; 32]>::try_from(leaf_value).unwrap());
    stdin.write(&<[u8; 32]>::try_from(expected_root).unwrap());

    client.prove(aptos_programs::MERKLE_PROGRAM, stdin).unwrap()
}

fn verify_and_ratchet_with_hash(trusted_state: &[u8], epoch_change_proof: &[u8]) -> HashValue {
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
        } => latest_epoch_change_li
            .ledger_info()
            .next_epoch_state()
            .expect("Expected epoch state")
            .verifier()
            .hash(),
        _ => panic!("Expected epoch change"),
    }
}
