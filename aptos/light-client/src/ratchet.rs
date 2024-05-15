use anyhow::Result;
use wp1_sdk::{ProverClient, SP1DefaultProof, SP1Stdin};

use crate::error::LightClientError;

#[allow(dead_code)]
struct RatchetOutput {
    prev_validator_verifier_hash: [u8; 32],
    new_validator_verifier_hash: [u8; 32],
}

#[inline]
pub fn generate_proof(
    client: &ProverClient,
    current_trusted_state: &[u8],
    epoch_change_proof: &[u8],
) -> Result<SP1DefaultProof> {
    let mut stdin = SP1Stdin::new();
    stdin.write(&current_trusted_state);
    stdin.write(&epoch_change_proof);
    let (pk, _) = client.setup(aptos_programs::RATCHET_PROGRAM);
    client.prove(&pk, stdin)
}

#[allow(dead_code)]
fn verify_and_ratchet(
    client: &ProverClient,
    current_trusted_state: &[u8],
    epoch_change_proof: &[u8],
) -> Result<(SP1DefaultProof, RatchetOutput), LightClientError> {
    wp1_sdk::utils::setup_logger();

    let mut proof =
        generate_proof(client, current_trusted_state, epoch_change_proof).map_err(|err| {
            LightClientError::ProvingError {
                program: "verify-and-ratchet".to_string(),
                source: err.into(),
            }
        })?;

    // Read output.
    let prev_validator_verifier_hash = proof.public_values.read::<[u8; 32]>();
    let new_validator_verifier_hash = proof.public_values.read::<[u8; 32]>();

    Ok((
        proof,
        RatchetOutput {
            prev_validator_verifier_hash,
            new_validator_verifier_hash,
        },
    ))
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use crate::error::LightClientError;
    use wp1_sdk::{ProverClient, SP1Stdin};

    fn execute_and_ratchet(
        current_trusted_state: &[u8],
        epoch_change_proof: &[u8],
    ) -> Result<(), LightClientError> {
        use wp1_sdk::utils;
        utils::setup_logger();

        let mut stdin = SP1Stdin::new();

        stdin.write(&current_trusted_state);
        stdin.write(&epoch_change_proof);

        ProverClient::execute(aptos_programs::RATCHET_PROGRAM, &stdin).map_err(|err| {
            LightClientError::ProvingError {
                program: "verify-and-ratchet".to_string(),
                source: err.into(),
            }
        })?;

        Ok(())
    }

    #[test]
    fn test_ratchet_execute() {
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use aptos_lc_core::NBR_VALIDATORS;
        use std::time::Instant;

        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper =
            AptosWrapper::new(20000, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let trusted_state_version = *aptos_wrapper.current_version();

        aptos_wrapper.generate_traffic().unwrap();

        let state_proof = aptos_wrapper
            .new_state_proof(trusted_state_version)
            .unwrap();

        let epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

        println!("Starting execution of verify_and_ratchet...");
        let start = Instant::now();
        execute_and_ratchet(&trusted_state, epoch_change_proof).unwrap();
        println!("Execution took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_ratchet_prove() {
        use super::*;
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use aptos_lc_core::crypto::hash::CryptoHash;
        use aptos_lc_core::types::trusted_state::TrustedState;
        use aptos_lc_core::NBR_VALIDATORS;
        use std::time::Instant;
        use wp1_sdk::ProverClient;

        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper =
            AptosWrapper::new(20000, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

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

        let start = Instant::now();
        println!("Starting generation of verify_and_ratchet proof...");
        let (proof, output) =
            verify_and_ratchet(&client, &trusted_state, epoch_change_proof).unwrap();
        println!("Proving took {:?}", start.elapsed());

        assert_eq!(
            output.prev_validator_verifier_hash,
            validator_verifier_hash.as_slice()
        );

        let (_, vk) = client.setup(aptos_programs::RATCHET_PROGRAM);
        let start = Instant::now();
        println!("Starting verification of verify_and_ratchet proof...");
        client.verify(&proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
