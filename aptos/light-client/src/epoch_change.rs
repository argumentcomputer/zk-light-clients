// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use anyhow::Result;
use wp1_sdk::{ProverClient, SP1Proof, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

use crate::error::LightClientError;

#[allow(dead_code)]
struct EpochChangeOutput {
    prev_validator_verifier_hash: [u8; 32],
    new_validator_verifier_hash: [u8; 32],
}

pub fn generate_stdin(current_trusted_state: &[u8], epoch_change_proof: &[u8]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&current_trusted_state);
    stdin.write(&epoch_change_proof);
    stdin
}

#[inline]
pub fn generate_keys(client: &ProverClient) -> (SP1ProvingKey, SP1VerifyingKey) {
    client.setup(aptos_programs::EPOCH_CHANGE_PROGRAM)
}

#[allow(dead_code)]
fn prove_epoch_change(
    client: &ProverClient,
    current_trusted_state: &[u8],
    epoch_change_proof: &[u8],
) -> Result<(SP1Proof, EpochChangeOutput), LightClientError> {
    wp1_sdk::utils::setup_logger();

    let stdin = generate_stdin(current_trusted_state, epoch_change_proof);
    let (pk, _) = generate_keys(client);

    let mut proof = client
        .prove(&pk, stdin)
        .map_err(|err| LightClientError::ProvingError {
            program: "prove-epoch-change".to_string(),
            source: err.into(),
        })?;

    // Read output.
    let prev_validator_verifier_hash = proof.public_values.read::<[u8; 32]>();
    let new_validator_verifier_hash = proof.public_values.read::<[u8; 32]>();

    Ok((
        proof,
        EpochChangeOutput {
            prev_validator_verifier_hash,
            new_validator_verifier_hash,
        },
    ))
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use crate::error::LightClientError;
    use wp1_sdk::{ProverClient, SP1Stdin};

    fn execute_epoch_change(
        current_trusted_state: &[u8],
        epoch_change_proof: &[u8],
    ) -> Result<(), LightClientError> {
        use wp1_sdk::utils;
        utils::setup_logger();

        let mut stdin = SP1Stdin::new();

        stdin.write(&current_trusted_state);
        stdin.write(&epoch_change_proof);

        let client = ProverClient::new();
        client
            .execute(aptos_programs::EPOCH_CHANGE_PROGRAM, &stdin)
            .map_err(|err| LightClientError::ProvingError {
                program: "prove-epoch-change".to_string(),
                source: err.into(),
            })?;

        Ok(())
    }

    #[test]
    fn test_execute_epoch_change() {
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use std::time::Instant;

        const NBR_VALIDATORS: usize = 130;
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

        println!("Starting execution of prove_epoch_change...");
        let start = Instant::now();
        execute_epoch_change(&trusted_state, epoch_change_proof).unwrap();
        println!("Execution took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_epoch_change() {
        use super::*;
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use aptos_lc_core::crypto::hash::CryptoHash;
        use aptos_lc_core::types::trusted_state::TrustedState;
        use std::time::Instant;
        use wp1_sdk::ProverClient;

        const NBR_VALIDATORS: usize = 130;
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
        println!("Starting generation of prove_epoch_change proof...");
        let (proof, output) =
            prove_epoch_change(&client, &trusted_state, epoch_change_proof).unwrap();
        println!("Proving took {:?}", start.elapsed());

        assert_eq!(
            output.prev_validator_verifier_hash,
            validator_verifier_hash.as_slice()
        );

        let (_, vk) = client.setup(aptos_programs::EPOCH_CHANGE_PROGRAM);
        let start = Instant::now();
        println!("Starting verification of prove_epoch_change proof...");
        client.verify(&proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
