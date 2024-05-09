use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::merkle::sparse_proof::SparseMerkleProof;
use aptos_lc_core::NBR_VALIDATORS;
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;
use wp1_sdk::{ProverClient, SP1CoreProof, SP1Stdin};

const NBR_LEAVES: [usize; 5] = [32, 128, 2048, 8192, 32768];

struct ProvingAssets {
    client: ProverClient,
    sparse_merkle_proof: SparseMerkleProof,
    leaf_key: [u8; 32],
    leaf_value: [u8; 32],
    expected_root: [u8; 32],
}

impl ProvingAssets {
    fn from_nbr_leaves(nbr_leaves: usize) -> Self {
        let mut aptos_wrapper = AptosWrapper::new(nbr_leaves, NBR_VALIDATORS, NBR_VALIDATORS);
        aptos_wrapper.generate_traffic();

        let proof_assets = aptos_wrapper
            .get_latest_proof_account(nbr_leaves - 1)
            .unwrap();

        let sparse_merkle_proof: SparseMerkleProof =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.state_proof()).unwrap()).unwrap();
        let leaf_key: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.key()).unwrap()).unwrap();
        let expected_root: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.root_hash()).unwrap()).unwrap();
        let leaf_value: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(&proof_assets.state_value_hash()).unwrap()).unwrap();

        let client = ProverClient::new();

        Self {
            client,
            sparse_merkle_proof,
            leaf_value,
            leaf_key,
            expected_root,
        }
    }

    fn prove(&self) -> SP1CoreProof {
        let mut stdin = SP1Stdin::new();

        stdin.write(&self.sparse_merkle_proof);
        stdin.write(&self.leaf_key);
        stdin.write(&self.leaf_value);
        stdin.write(&self.expected_root);

        self.client
            .prove(aptos_programs::MERKLE_PROGRAM, &stdin)
            .unwrap()
    }

    fn verify(&self, proof: &SP1CoreProof) {
        self.client
            .verify(aptos_programs::MERKLE_PROGRAM, proof)
            .expect("Verification failed");
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
        let proof = proving_assets.prove();
        let proving_time = start_proving.elapsed();

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
