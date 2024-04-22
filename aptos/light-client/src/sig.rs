use crate::error::LightClientError;
use wp1_sdk::utils::BabyBearPoseidon2;
use wp1_sdk::{ProverClient, SP1ProofWithIO, SP1Stdin};

#[allow(dead_code)]
fn sig_verification(
    client: &ProverClient,
    ledger_info_w_sig: Vec<u8>,
) -> Result<(SP1ProofWithIO<BabyBearPoseidon2>, bool), LightClientError> {
    #[cfg(debug_assertions)]
    {
        use wp1_sdk::utils;
        utils::setup_logger();
    }

    let mut stdin = SP1Stdin::new();

    stdin.write(&ledger_info_w_sig);

    let mut proof = client
        .prove(aptos_programs::SIGNATURE_VERIFICATION_PROGRAM, stdin)
        .map_err(|err| LightClientError::ProvingError {
            program: "signature-verification".to_string(),
            source: err.into(),
        })?;

    // Read output.
    let success = proof.public_values.read::<bool>();

    Ok((proof, success))
}
