use anyhow::Result;
use getset::Getters;
use serde::{Deserialize, Serialize};
use wp1_sdk::{ProverClient, SP1DefaultProof, SP1Stdin};

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

#[allow(dead_code)]
struct MerkleOutput {
    validator_verifier_hash: [u8; 32],
    state_hash: [u8; 32],
}

#[inline]
pub fn generate_proof(
    client: &ProverClient,
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> Result<SP1DefaultProof> {
    let mut stdin = SP1Stdin::new();

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

    let (pk, _) = client.setup(aptos_programs::MERKLE_PROGRAM);

    client.prove(&pk, stdin)
}

#[allow(dead_code)]
fn merkle_proving(
    client: &ProverClient,
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> Result<(SP1DefaultProof, MerkleOutput), LightClientError> {
    wp1_sdk::utils::setup_logger();

    let mut proof = generate_proof(
        client,
        sparse_merkle_proof_assets,
        transaction_proof_assets,
        validator_verifier_assets,
    )
    .map_err(|err| LightClientError::ProvingError {
        program: "merkle".to_string(),
        source: err.into(),
    })?;

    // Read output.
    let validator_verifier_hash = proof.public_values.read::<[u8; 32]>();
    let state_hash = proof.public_values.read::<[u8; 32]>();

    Ok((
        proof,
        MerkleOutput {
            validator_verifier_hash,
            state_hash,
        },
    ))
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use crate::error::LightClientError;
    use crate::merkle::{SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets};
    use aptos_lc_core::types::validator::ValidatorVerifier;
    use wp1_sdk::{ProverClient, SP1Stdin};

    fn setup_assets() -> (
        SparseMerkleProofAssets,
        TransactionProofAssets,
        ValidatorVerifierAssets,
    ) {
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use aptos_lc_core::types::trusted_state::TrustedState;
        use aptos_lc_core::NBR_VALIDATORS;

        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper =
            AptosWrapper::new(500, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();
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

    fn merkle_execute(
        sparse_merkle_proof_assets: &SparseMerkleProofAssets,
        transaction_proof_assets: &TransactionProofAssets,
        validator_verifier_assets: &ValidatorVerifierAssets,
    ) -> Result<(), LightClientError> {
        use wp1_sdk::utils;
        utils::setup_logger();

        let mut stdin = SP1Stdin::new();

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

        ProverClient::execute(aptos_programs::MERKLE_PROGRAM, &stdin).map_err(|err| {
            LightClientError::ProvingError {
                program: "merkle".to_string(),
                source: err.into(),
            }
        })?;

        Ok(())
    }

    #[test]
    fn test_merkle_execute() {
        use std::time::Instant;

        let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
            setup_assets();

        println!("Starting execution of Merkle inclusion...");
        let start = Instant::now();
        merkle_execute(
            &sparse_merkle_proof_assets,
            &transaction_proof_assets,
            &validator_verifier_assets,
        )
        .unwrap();
        println!("Execution took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_merkle() {
        use super::*;
        use aptos_lc_core::crypto::hash::CryptoHash;
        use std::time::Instant;
        use wp1_sdk::ProverClient;
        let client = ProverClient::new();

        let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
            setup_assets();

        let start = Instant::now();
        println!("Starting generation of Merkle inclusion proof...");
        let (proof, output) = merkle_proving(
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

        let (_, vk) = client.setup(aptos_programs::MERKLE_PROGRAM);
        let start = Instant::now();
        println!("Starting verification of Merkle inclusion proof...");
        client.verify(&proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
