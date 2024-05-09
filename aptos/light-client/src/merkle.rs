use crate::error::LightClientError;
use wp1_sdk::{ProverClient, SP1PublicValues, SP1Stdin};

#[allow(dead_code)]
fn merkle_proving(
    client: &ProverClient,
    sparse_merkle_proof: &[u8],
    leaf_key: [u8; 32],
    leaf_hash: [u8; 32],
    expected_root_hash: [u8; 32],
) -> Result<(SP1PublicValues, [u8; 32]), LightClientError> {
    use wp1_sdk::utils;
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    stdin.write(&sparse_merkle_proof);
    stdin.write(&leaf_key);
    stdin.write(&leaf_hash);
    stdin.write(&expected_root_hash);

    let mut proof = client
        .prove(aptos_programs::MERKLE_PROGRAM, &stdin)
        .map_err(|err| LightClientError::ProvingError {
            program: "merkle".to_string(),
            source: err.into(),
        })?;

    // Read output.
    let expected_root_hash = proof.public_values.read::<[u8; 32]>();

    Ok((proof.public_values, expected_root_hash))
}

#[cfg(feature = "aptos")]
#[cfg(test)]
mod test {
    use crate::error::LightClientError;
    use wp1_sdk::{ProverClient, SP1Stdin};

    fn merkle_execute(
        sparse_merkle_proof: &[u8],
        leaf_key: [u8; 32],
        leaf_hash: [u8; 32],
        expected_root_hash: [u8; 32],
    ) -> Result<(), LightClientError> {
        use wp1_sdk::utils;
        utils::setup_logger();

        let mut stdin = SP1Stdin::new();

        stdin.write(&sparse_merkle_proof);
        stdin.write(&leaf_key);
        stdin.write(&leaf_hash);
        stdin.write(&expected_root_hash);

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
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use std::time::Instant;

        let mut aptos_wrapper = AptosWrapper::new(500, 1, 1);
        aptos_wrapper.generate_traffic();

        let proof_assets = aptos_wrapper.get_latest_proof_account(400).unwrap();

        let intern_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
        let key: [u8; 32] = *proof_assets.key().as_ref();
        let root_hash: [u8; 32] = *proof_assets.root_hash().as_ref();
        let element_hash: [u8; 32] = *proof_assets.state_value_hash().as_ref();

        println!(
            "Starting execution of Merkle inclusion with {} siblings...",
            proof_assets.state_proof().siblings().len()
        );
        let start = Instant::now();
        merkle_execute(&intern_proof, key, element_hash, root_hash).unwrap();
        println!("Execution took {:?}", start.elapsed());
    }

    #[test]
    fn test_merkle_prove() {
        use super::*;
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use std::time::Instant;
        use wp1_sdk::ProverClient;

        let mut aptos_wrapper = AptosWrapper::new(500, 1, 1);
        aptos_wrapper.generate_traffic();

        let proof_assets = aptos_wrapper.get_latest_proof_account(400).unwrap();

        let intern_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
        let key: [u8; 32] = *proof_assets.key().as_ref();
        let root_hash: [u8; 32] = *proof_assets.root_hash().as_ref();
        let element_hash: [u8; 32] = *proof_assets.state_value_hash().as_ref();

        let client = ProverClient::new();

        let start = Instant::now();
        println!(
            "Starting generation of Merkle inclusion proof with {} siblings...",
            proof_assets.state_proof().siblings().len()
        );
        let (proof, res) =
            merkle_proving(&client, &intern_proof, key, element_hash, root_hash).unwrap();
        assert_eq!(res, root_hash);
        println!("Proving took {:?}", start.elapsed());

        let start = Instant::now();
        println!("Starting verification of Merkle inclusion proof...");
        client
            .verify(aptos_programs::MERKLE_PROGRAM, &proof)
            .unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
