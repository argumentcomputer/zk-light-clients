use crate::error::LightClientError;
use wp1_sdk::utils::BabyBearPoseidon2;
use wp1_sdk::{ProverClient, SP1ProofWithIO, SP1Stdin};

#[allow(dead_code)]
fn verify_and_ratchet(
    client: &ProverClient,
    current_trusted_state: &[u8],
    epoch_change_proof: &[u8],
    validator_verifier_hash: &[u8],
) -> Result<(SP1ProofWithIO<BabyBearPoseidon2>, [u8; 32]), LightClientError> {
    use wp1_sdk::utils;
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    stdin.write(&current_trusted_state);
    stdin.write(&epoch_change_proof);
    stdin.write(&validator_verifier_hash);

    let mut proof = client
        .prove(aptos_programs::RATCHET_PROGRAM, stdin)
        .map_err(|err| LightClientError::ProvingError {
            program: "verify-and-ratchet".to_string(),
            source: err.into(),
        })?;

    // Read output.
    let new_validator_verifier_hash = proof.public_values.read::<[u8; 32]>();

    Ok((proof, new_validator_verifier_hash))
}

#[cfg(test)]
mod test {
    #[cfg(feature = "aptos")]
    #[test]
    fn test_ratchet() {
        use super::*;
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use aptos_lc_core::crypto::hash::CryptoHash;
        use aptos_lc_core::types::trusted_state::TrustedState;
        use aptos_lc_core::NBR_VALIDATORS;
        use std::time::Instant;
        use wp1_sdk::ProverClient;

        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper = AptosWrapper::new(30000, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR);

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier_hash = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash().to_vec(),
            _ => panic!("Expected epoch change for current trusted state"),
        };
        let trusted_state_version = *aptos_wrapper.current_version();

        aptos_wrapper.generate_traffic();

        let state_proof = aptos_wrapper.new_state_proof(trusted_state_version);

        let epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

        let client = ProverClient::new();

        let start = Instant::now();
        println!("Starting generation of verify_and_ratchet proof...");
        let (proof, _) = verify_and_ratchet(
            &client,
            &trusted_state,
            epoch_change_proof,
            &validator_verifier_hash,
        )
        .unwrap();
        println!("Proving took {:?}", start.elapsed());

        let start = Instant::now();
        println!("Starting verification of verify_and_ratchet proof...");
        client
            .verify(aptos_programs::RATCHET_PROGRAM, &proof)
            .unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}