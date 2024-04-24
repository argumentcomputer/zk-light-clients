use crate::error::LightClientError;
use wp1_sdk::utils::BabyBearPoseidon2;
use wp1_sdk::{ProverClient, SP1ProofWithIO, SP1Stdin};

#[allow(dead_code)]
fn verify_and_ratchet(
    client: &ProverClient,
    current_trusted_state: &[u8],
    epoch_change_proof: &[u8],
) -> Result<(SP1ProofWithIO<BabyBearPoseidon2>, bool), LightClientError> {
    #[cfg(debug_assertions)]
    {
        use wp1_sdk::utils;
        utils::setup_logger();
    }

    let mut stdin = SP1Stdin::new();

    stdin.write(&current_trusted_state);
    stdin.write(&epoch_change_proof);

    let mut proof = client
        .prove(aptos_programs::RATCHET_PROGRAM, stdin)
        .map_err(|err| LightClientError::ProvingError {
            program: "verify-and-ratchet".to_string(),
            source: err.into(),
        })?;

    // Read output.
    let success = proof.public_values.read::<bool>();

    Ok((proof, success))
}
