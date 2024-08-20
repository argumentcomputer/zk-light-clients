// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: BUSL-1.1

use anyhow::Result;
use sphinx_sdk::{
    ProverClient, SphinxProofWithPublicValues, SphinxProvingKey, SphinxStdin, SphinxVerifyingKey,
};

use crate::error::LightClientError;

#[allow(dead_code)]
struct EpochChangeOutput {
    prev_validator_verifier_hash: [u8; 32],
    new_validator_verifier_hash: [u8; 32],
}

#[cfg(feature = "aptos")]
pub fn setup_assets() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
    use aptos_lc_core::crypto::hash::CryptoHash;

    const NBR_VALIDATORS: usize = 130;
    const AVERAGE_SIGNERS_NBR: usize = 95;

    let mut aptos_wrapper = AptosWrapper::new(20000, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

    let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
    let validator_verifier_hash =
        match aptos_lc_core::types::trusted_state::TrustedState::from_bytes(&trusted_state).unwrap()
        {
            aptos_lc_core::types::trusted_state::TrustedState::EpochState {
                epoch_state, ..
            } => epoch_state.verifier().hash().to_vec(),
            _ => panic!("Expected epoch change for current trusted state"),
        };
    let trusted_state_version = *aptos_wrapper.current_version();

    aptos_wrapper.generate_traffic().unwrap();

    let state_proof = aptos_wrapper
        .new_state_proof(trusted_state_version)
        .unwrap();

    let epoch_change_proof = bcs::to_bytes(state_proof.epoch_changes()).unwrap();

    (trusted_state, epoch_change_proof, validator_verifier_hash)
}

pub fn generate_stdin(current_trusted_state: &[u8], epoch_change_proof: &[u8]) -> SphinxStdin {
    let mut stdin = SphinxStdin::new();
    stdin.write(&current_trusted_state);
    stdin.write(&epoch_change_proof);
    stdin
}

#[inline]
pub fn generate_keys(client: &ProverClient) -> (SphinxProvingKey, SphinxVerifyingKey) {
    client.setup(aptos_programs::EPOCH_CHANGE_PROGRAM)
}

#[allow(dead_code)]
fn prove_epoch_change(
    client: &ProverClient,
    current_trusted_state: &[u8],
    epoch_change_proof: &[u8],
) -> Result<(SphinxProofWithPublicValues, EpochChangeOutput), LightClientError> {
    sphinx_sdk::utils::setup_logger();

    let stdin = generate_stdin(current_trusted_state, epoch_change_proof);
    let (pk, _) = generate_keys(client);

    let mut proof =
        client
            .prove(&pk, stdin)
            .run()
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
    use crate::epoch_change::setup_assets;
    use crate::error::LightClientError;
    use sphinx_sdk::artifacts::try_install_plonk_bn254_artifacts;
    use sphinx_sdk::utils::setup_logger;
    use sphinx_sdk::{ProverClient, SphinxStdin};

    fn execute_epoch_change(
        current_trusted_state: &[u8],
        epoch_change_proof: &[u8],
    ) -> Result<(), LightClientError> {
        setup_logger();

        let mut stdin = SphinxStdin::new();

        stdin.write(&current_trusted_state);
        stdin.write(&epoch_change_proof);

        let client = ProverClient::new();
        client
            .execute(aptos_programs::EPOCH_CHANGE_PROGRAM, stdin)
            .run()
            .map_err(|err| LightClientError::ProvingError {
                program: "prove-epoch-change".to_string(),
                source: err.into(),
            })?;

        Ok(())
    }

    #[test]
    fn test_execute_epoch_change() {
        use std::time::Instant;

        let (trusted_state, epoch_change_proof, _) = setup_assets();

        println!("Starting execution of prove_epoch_change...");
        let start = Instant::now();
        execute_epoch_change(&trusted_state, &epoch_change_proof).unwrap();
        println!("Execution took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_epoch_change() {
        use super::*;
        use sphinx_sdk::ProverClient;
        use std::time::Instant;

        let (trusted_state, epoch_change_proof, validator_verifier_hash) = setup_assets();

        let client = ProverClient::new();

        let start = Instant::now();
        println!("Starting generation of prove_epoch_change proof...");
        let (proof, output) =
            prove_epoch_change(&client, &trusted_state, &epoch_change_proof).unwrap();
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

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_snark_prove_epoch_change() {
        use super::*;
        use sphinx_sdk::ProverClient;
        use std::time::Instant;

        setup_logger();

        let (trusted_state, epoch_change_proof, _) = setup_assets();

        let client = ProverClient::new();
        let (pk, vk) = client.setup(aptos_programs::EPOCH_CHANGE_PROGRAM);

        let stdin = generate_stdin(trusted_state.as_slice(), &epoch_change_proof);

        // Install PLONK artifacts.
        try_install_plonk_bn254_artifacts(false);

        let start = Instant::now();
        println!("Starting generation of prove_epoch_change proof...");
        let snark_proof = client.prove(&pk, stdin).plonk().run().unwrap();
        println!("Proving took {:?}", start.elapsed());

        let start = Instant::now();
        println!("Starting verification of prove_epoch_change proof...");
        client.verify(&snark_proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
