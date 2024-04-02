use crate::error::LightClientError;
use aptos_lc_core::merkle::proof::SparseMerkleProof;
use wp1_sdk::utils::BabyBearPoseidon2;
use wp1_sdk::{SP1ProofWithIO, SP1Prover, SP1Stdin};

#[allow(dead_code)]
fn merkle_proving(
    sparse_merkle_proof: SparseMerkleProof,
    leaf_key: [u8; 32],
    leaf_hash: [u8; 32],
    expected_root_hash: [u8; 32],
) -> Result<(SP1ProofWithIO<BabyBearPoseidon2>, [u8; 32]), LightClientError> {
    #[cfg(debug_assertions)]
    {
        use wp1_sdk::utils;
        utils::setup_logger();
    }

    let mut stdin = SP1Stdin::new();

    stdin.write(&sparse_merkle_proof);
    stdin.write(&leaf_key);
    stdin.write(&leaf_hash);
    stdin.write(&expected_root_hash);

    let mut proof = SP1Prover::prove(aptos_programs::MERKLE_PROGRAM, stdin).map_err(|err| {
        LightClientError::ProvingError {
            program: "merkle".to_string(),
            source: err.into(),
        }
    })?;

    // Read output.
    let expected_root_hash = proof.stdout.read::<[u8; 32]>();

    Ok((proof, expected_root_hash))
}

#[cfg(test)]
mod test {
    #[cfg(feature = "aptos")]
    #[test]
    fn test_merkle() {
        use super::*;
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use std::time::Instant;
        use wp1_sdk::SP1Verifier;

        let mut aptos_wrapper = AptosWrapper::new(30000, 1);
        aptos_wrapper.generate_traffic();

        let proof_assets = aptos_wrapper.get_latest_proof_account(25000).unwrap();

        let intern_proof: SparseMerkleProof =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.state_proof()).unwrap()).unwrap();
        let key: [u8; 32] = bcs::from_bytes(&bcs::to_bytes(proof_assets.key()).unwrap()).unwrap();
        let root_hash: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.root_hash()).unwrap()).unwrap();
        let element_hash: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(&proof_assets.state_value_hash()).unwrap()).unwrap();

        let start = Instant::now();
        println!(
            "Starting generation of Merkle inclusion proof with {} siblings...",
            proof_assets.state_proof().siblings().len()
        );
        let (proof, res) = merkle_proving(intern_proof, key, element_hash, root_hash).unwrap();
        assert_eq!(res, root_hash);
        println!("Proving took {:?}", start.elapsed());

        let start = Instant::now();
        println!("Starting verification of Merkle inclusion proof...");
        SP1Verifier::verify(&aptos_programs::MERKLE_PROGRAM, &proof).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
