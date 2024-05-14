use aptos_lc::merkle::{SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets};
use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::trusted_state::TrustedState;
use aptos_lc_core::types::validator::ValidatorVerifier;
use aptos_lc_core::NBR_VALIDATORS;
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;
use wp1_sdk::utils::setup_logger;
use wp1_sdk::{ProverClient, SP1DefaultProof, SP1Stdin};

const NBR_LEAVES: [usize; 5] = [32, 128, 2048, 8192, 32768];
const AVERAGE_SIGNERS_NBR: usize = 95;

struct ProvingAssets {
    client: ProverClient,
    sparse_merkle_proof_assets: SparseMerkleProofAssets,
    transaction_proof_assets: TransactionProofAssets,
    validator_verifier_assets: ValidatorVerifierAssets,
}

impl ProvingAssets {
    fn from_nbr_leaves(nbr_leaves: usize) -> Self {
        let mut aptos_wrapper =
            AptosWrapper::new(nbr_leaves, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().clone(),
            _ => panic!("expected epoch state"),
        };

        let proof_assets = aptos_wrapper
            .get_latest_proof_account(nbr_leaves - 1)
            .unwrap();

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

        let client = ProverClient::new();

        Self {
            client,
            sparse_merkle_proof_assets,
            transaction_proof_assets,
            validator_verifier_assets,
        }
    }

    fn prove(&self) -> SP1DefaultProof {
        let mut stdin = SP1Stdin::new();

        setup_logger();

        // Account inclusion input
        stdin.write(self.sparse_merkle_proof_assets.sparse_merkle_proof());
        stdin.write(self.sparse_merkle_proof_assets.leaf_key());
        stdin.write(self.sparse_merkle_proof_assets.leaf_hash());

        // Tx inclusion input
        stdin.write(self.transaction_proof_assets.transaction());
        stdin.write(self.transaction_proof_assets.transaction_index());
        stdin.write(self.transaction_proof_assets.transaction_proof());
        stdin.write(self.transaction_proof_assets.latest_li());

        // Validator verifier
        stdin.write(self.validator_verifier_assets.validator_verifier());

        let (pk, _) = self.client.setup(aptos_programs::MERKLE_PROGRAM);
        self.client.prove(&pk, stdin).unwrap()
    }

    fn verify(&self, proof: &SP1DefaultProof) {
        let (_, vk) = self.client.setup(aptos_programs::MERKLE_PROGRAM);
        self.client.verify(proof, &vk).expect("Verification failed");
    }
}

#[derive(Serialize)]
struct Timings {
    nbr_leaves: usize,
    proving_time: u128,
    verifying_time: u128,
}

fn main() {
    for nbr_leaves in NBR_LEAVES {
        let proving_assets = ProvingAssets::from_nbr_leaves(nbr_leaves);

        let start_proving = Instant::now();
        let mut proof = proving_assets.prove();
        let proving_time = start_proving.elapsed();

        // Assert that we received proper outputs
        let prev_validator_verifier_hash = proof.public_values.read::<[u8; 32]>();

        assert_eq!(
            &prev_validator_verifier_hash,
            ValidatorVerifier::from_bytes(
                proving_assets
                    .validator_verifier_assets
                    .validator_verifier()
            )
            .unwrap()
            .hash()
            .as_ref()
        );

        let start_verifying = Instant::now();
        proving_assets.verify(black_box(&proof));
        let verifying_time = start_verifying.elapsed();

        let timings = Timings {
            nbr_leaves,
            proving_time: proving_time.as_millis(),
            verifying_time: verifying_time.as_millis(),
        };

        let json_output = serde_json::to_string(&timings).unwrap();
        println!("{}", json_output);
    }
}
