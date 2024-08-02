// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use getset::Getters;
use serde::{Deserialize, Serialize};
use sphinx_sdk::{
    ProverClient, SphinxProofWithPublicValues, SphinxProvingKey, SphinxStdin, SphinxVerifyingKey,
};

use crate::error::LightClientError;

#[derive(Clone, Debug, Getters, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct SparseMerkleProofAssets {
    sparse_merkle_proof: Vec<u8>,
    leaf_key: [u8; 32],
    leaf_hash: [u8; 32],
}

impl SparseMerkleProofAssets {
    pub fn new(
        sparse_merkle_proof: Vec<u8>,
        leaf_key: [u8; 32],
        leaf_hash: [u8; 32],
    ) -> SparseMerkleProofAssets {
        SparseMerkleProofAssets {
            sparse_merkle_proof,
            leaf_key,
            leaf_hash,
        }
    }
}

#[derive(Clone, Debug, Getters, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct TransactionProofAssets {
    transaction: Vec<u8>,
    transaction_index: u64,
    transaction_proof: Vec<u8>,
    latest_li: Vec<u8>,
}

impl TransactionProofAssets {
    pub fn new(
        transaction: Vec<u8>,
        transaction_index: u64,
        transaction_proof: Vec<u8>,
        latest_li: Vec<u8>,
    ) -> TransactionProofAssets {
        TransactionProofAssets {
            transaction,
            transaction_index,
            transaction_proof,
            latest_li,
        }
    }
}

#[derive(Clone, Debug, Getters, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct ValidatorVerifierAssets {
    validator_verifier: Vec<u8>,
}

impl ValidatorVerifierAssets {
    pub fn new(validator_verifier: Vec<u8>) -> ValidatorVerifierAssets {
        ValidatorVerifierAssets { validator_verifier }
    }
}

#[cfg(feature = "aptos")]
pub fn setup_assets() -> (
    SparseMerkleProofAssets,
    TransactionProofAssets,
    ValidatorVerifierAssets,
) {
    use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
    use aptos_lc_core::types::trusted_state::TrustedState;

    const NBR_VALIDATORS: usize = 130;
    const AVERAGE_SIGNERS_NBR: usize = 95;

    let mut aptos_wrapper = AptosWrapper::new(500, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();
    aptos_wrapper.generate_traffic().unwrap();

    let proof_assets = aptos_wrapper.get_latest_proof_account(400).unwrap();

    let sparse_merkle_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
    let key: [u8; 32] = *proof_assets.key().as_ref();
    let element_hash: [u8; 32] = *proof_assets.state_value_hash().unwrap().as_ref();

    let transaction = bcs::to_bytes(&proof_assets.transaction()).unwrap();
    let transaction_proof = bcs::to_bytes(&proof_assets.transaction_proof()).unwrap();

    let latest_li = aptos_wrapper.get_latest_li_bytes().unwrap();

    let validator_verifier =
        match TrustedState::from_bytes(&bcs::to_bytes(&aptos_wrapper.trusted_state()).unwrap())
            .unwrap()
        {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().clone(),
            _ => panic!("expected epoch state"),
        };

    let sparse_merkle_proof_assets = SparseMerkleProofAssets {
        sparse_merkle_proof,
        leaf_key: key,
        leaf_hash: element_hash,
    };

    let transaction_proof_assets = TransactionProofAssets {
        transaction,
        transaction_index: *proof_assets.transaction_version(),
        transaction_proof,
        latest_li,
    };

    let validator_verifier_assets = ValidatorVerifierAssets {
        validator_verifier: validator_verifier.to_bytes(),
    };

    (
        sparse_merkle_proof_assets,
        transaction_proof_assets,
        validator_verifier_assets,
    )
}

pub fn generate_stdin(
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> SphinxStdin {
    let mut stdin = SphinxStdin::new();
    // Account inclusion input
    stdin.write(&sparse_merkle_proof_assets.sparse_merkle_proof);
    stdin.write(&sparse_merkle_proof_assets.leaf_key);
    stdin.write(&sparse_merkle_proof_assets.leaf_hash);

    // Tx inclusion input
    stdin.write(&transaction_proof_assets.transaction);
    stdin.write(&transaction_proof_assets.transaction_index);
    stdin.write(&transaction_proof_assets.transaction_proof);
    stdin.write(&transaction_proof_assets.latest_li);

    // Validator verifier
    stdin.write(&validator_verifier_assets.validator_verifier);

    stdin
}

#[inline]
pub fn generate_keys(client: &ProverClient) -> (SphinxProvingKey, SphinxVerifyingKey) {
    client.setup(aptos_programs::INCLUSION_PROGRAM)
}

#[allow(dead_code)]
struct InclusionOutput {
    validator_verifier_hash: [u8; 32],
    state_hash: [u8; 32],
    block_hash: [u8; 32],
    key: [u8; 32],
    value: [u8; 32],
}

#[allow(dead_code)]
fn prove_inclusion(
    client: &ProverClient,
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> Result<(SphinxProofWithPublicValues, InclusionOutput), LightClientError> {
    sphinx_sdk::utils::setup_logger();

    let stdin = generate_stdin(
        sparse_merkle_proof_assets,
        transaction_proof_assets,
        validator_verifier_assets,
    );
    let (pk, _) = generate_keys(client);

    let mut proof =
        client
            .prove(&pk, stdin)
            .run()
            .map_err(|err| LightClientError::ProvingError {
                program: "prove-merkle-inclusion".to_string(),
                source: err.into(),
            })?;

    // Read output.
    let validator_verifier_hash = proof.public_values.read::<[u8; 32]>();
    let state_hash = proof.public_values.read::<[u8; 32]>();
    let block_hash = proof.public_values.read::<[u8; 32]>();
    let key = proof.public_values.read::<[u8; 32]>();
    let value = proof.public_values.read::<[u8; 32]>();

    Ok((
        proof,
        InclusionOutput {
            validator_verifier_hash,
            state_hash,
            block_hash,
            key,
            value,
        },
    ))
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use crate::error::LightClientError;
    use crate::inclusion::{
        setup_assets, SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
    };
    use aptos_lc_core::types::validator::ValidatorVerifier;
    use sphinx_sdk::artifacts::try_install_plonk_bn254_artifacts;
    use sphinx_sdk::utils::setup_logger;
    use sphinx_sdk::{ProverClient, SphinxStdin};

    fn execute_inclusion(
        sparse_merkle_proof_assets: &SparseMerkleProofAssets,
        transaction_proof_assets: &TransactionProofAssets,
        validator_verifier_assets: &ValidatorVerifierAssets,
    ) -> Result<(), LightClientError> {
        setup_logger();

        let mut stdin = SphinxStdin::new();

        // Account inclusion input
        stdin.write(&sparse_merkle_proof_assets.sparse_merkle_proof);
        stdin.write(&sparse_merkle_proof_assets.leaf_key);
        stdin.write(&sparse_merkle_proof_assets.leaf_hash);

        // Tx inclusion input
        stdin.write(&transaction_proof_assets.transaction);
        stdin.write(&transaction_proof_assets.transaction_index);
        stdin.write(&transaction_proof_assets.transaction_proof);
        stdin.write(&transaction_proof_assets.latest_li);

        // Validator verifier
        stdin.write(&validator_verifier_assets.validator_verifier);

        let client = ProverClient::new();
        client
            .execute(aptos_programs::INCLUSION_PROGRAM, stdin)
            .run()
            .map_err(|err| LightClientError::ProvingError {
                program: "prove-merkle-inclusion".to_string(),
                source: err.into(),
            })?;

        Ok(())
    }

    #[test]
    fn test_execute_inclusion() {
        use std::time::Instant;

        let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
            setup_assets();

        println!("Starting execution of inclusion...");
        let start = Instant::now();
        execute_inclusion(
            &sparse_merkle_proof_assets,
            &transaction_proof_assets,
            &validator_verifier_assets,
        )
        .unwrap();
        println!("Execution took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_inclusion() {
        use super::*;
        use aptos_lc_core::crypto::hash::CryptoHash;
        use sphinx_sdk::ProverClient;
        use std::time::Instant;
        let client = ProverClient::new();

        let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
            setup_assets();

        let start = Instant::now();
        println!("Starting generation of inclusion proof...");
        let (proof, output) = prove_inclusion(
            &client,
            &sparse_merkle_proof_assets,
            &transaction_proof_assets,
            &validator_verifier_assets,
        )
        .unwrap();

        assert_eq!(
            &output.validator_verifier_hash,
            ValidatorVerifier::from_bytes(validator_verifier_assets.validator_verifier())
                .unwrap()
                .hash()
                .as_ref()
        );

        println!("Proving took {:?}", start.elapsed());

        let (_, vk) = client.setup(aptos_programs::INCLUSION_PROGRAM);
        let start = Instant::now();
        println!("Starting verification of inclusion proof...");
        client.verify(&proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_snark_prove_inclusion() {
        use super::*;
        use sphinx_sdk::ProverClient;
        use std::time::Instant;

        setup_logger();

        let client = ProverClient::new();
        let (pk, vk) = client.setup(aptos_programs::INCLUSION_PROGRAM);

        let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
            setup_assets();

        let stdin = generate_stdin(
            &sparse_merkle_proof_assets,
            &transaction_proof_assets,
            &validator_verifier_assets,
        );

        // Install PLONK artifacts.
        try_install_plonk_bn254_artifacts(false);

        let start = Instant::now();
        println!("Starting generation of inclusion proof...");
        let snark_proof = client.prove(&pk, stdin).plonk().run().unwrap();
        println!("Proving took {:?}", start.elapsed());

        let start = Instant::now();
        println!("Starting verification of inclusion proof...");
        client.verify(&snark_proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
