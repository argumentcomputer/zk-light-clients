use crate::error::LightClientError;
use getset::Getters;
use wp1_sdk::{ProverClient, SP1CoreProof, SP1Stdin};

#[derive(Clone, Debug, Getters)]
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

#[derive(Clone, Debug, Getters)]
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

#[derive(Clone, Debug, Getters)]
#[getset(get = "pub")]
pub struct ValidatorVerifierAssets {
    validator_verifier: Vec<u8>,
    validator_hash: [u8; 32],
}

impl ValidatorVerifierAssets {
    pub fn new(validator_verifier: Vec<u8>, validator_hash: [u8; 32]) -> ValidatorVerifierAssets {
        ValidatorVerifierAssets {
            validator_verifier,
            validator_hash,
        }
    }
}

#[allow(dead_code)]
fn merkle_proving(
    client: &ProverClient,
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> Result<(SP1CoreProof, [u8; 32]), LightClientError> {
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
    stdin.write(&validator_verifier_assets.validator_hash);

    let mut proof = client
        .prove(aptos_programs::MERKLE_PROGRAM, &stdin)
        .map_err(|err| LightClientError::ProvingError {
            program: "merkle".to_string(),
            source: err.into(),
        })?;

    // Read output.
    let expected_root_hash = proof.public_values.read::<[u8; 32]>();

    Ok((proof, expected_root_hash))
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use crate::error::LightClientError;
    use crate::merkle::{SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets};
    use wp1_sdk::{ProverClient, SP1Stdin};

    fn setup_assets() -> (
        SparseMerkleProofAssets,
        TransactionProofAssets,
        ValidatorVerifierAssets,
    ) {
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use aptos_lc_core::crypto::hash::CryptoHash;
        use aptos_lc_core::types::trusted_state::TrustedState;
        use aptos_lc_core::NBR_VALIDATORS;

        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper = AptosWrapper::new(500, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR);
        aptos_wrapper.generate_traffic();

        let proof_assets = aptos_wrapper.get_latest_proof_account(400).unwrap();

        let sparse_merkle_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
        let key: [u8; 32] = *proof_assets.key().as_ref();
        let element_hash: [u8; 32] = *proof_assets.state_value_hash().as_ref();

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

        let validator_verifier_hash = validator_verifier.hash();

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
            validator_hash: *validator_verifier_hash.as_ref(),
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
        stdin.write(&validator_verifier_assets.validator_hash);

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
    fn test_merkle() {
        use super::*;
        use std::time::Instant;
        use wp1_sdk::ProverClient;
        let client = ProverClient::new();

        let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
            setup_assets();

        let start = Instant::now();
        println!("Starting generation of Merkle inclusion proof...");
        let (proof, _) = merkle_proving(
            &client,
            &sparse_merkle_proof_assets,
            &transaction_proof_assets,
            &validator_verifier_assets,
        )
        .unwrap();

        println!("Proving took {:?}", start.elapsed());

        let start = Instant::now();
        println!("Starting verification of Merkle inclusion proof...");
        client
            .verify(aptos_programs::MERKLE_PROGRAM, &proof)
            .unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
