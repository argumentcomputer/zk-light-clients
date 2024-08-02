// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::LightClientError;
use sphinx_sdk::{ProverClient, SphinxProof, SphinxStdin};

#[allow(dead_code)]
fn sig_verification(
    client: &ProverClient,
    ledger_info_w_sig: &[u8],
) -> Result<(SphinxProof, bool), LightClientError> {
    use sphinx_sdk::utils;
    utils::setup_logger();

    let mut stdin = SphinxStdin::new();

    stdin.write(&ledger_info_w_sig);

    let (pk, _) = client.setup(aptos_programs::bench::SIGNATURE_VERIFICATION_PROGRAM);
    let mut proof = client
        .prove(&pk, stdin)
        .map_err(|err| LightClientError::ProvingError {
            program: "signature-verification".to_string(),
            source: err.into(),
        })?;

    // Read output.
    let success = proof.public_values.read::<bool>();

    Ok((proof, success))
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use crate::error::LightClientError;
    use sphinx_sdk::utils::setup_logger;
    use sphinx_sdk::{ProverClient, SphinxStdin};

    fn sig_execute(ledger_info_w_sig: &[u8]) -> Result<(), LightClientError> {
        setup_logger();

        let mut stdin = SphinxStdin::new();

        stdin.write(&ledger_info_w_sig);

        let client = ProverClient::new();
        client
            .execute(
                aptos_programs::bench::SIGNATURE_VERIFICATION_PROGRAM,
                &stdin,
            )
            .map_err(|err| LightClientError::ProvingError {
                program: "signature-verification".to_string(),
                source: err.into(),
            })?;

        Ok(())
    }

    #[test]
    fn test_execute_sig() {
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use std::time::Instant;

        const NBR_VALIDATORS: usize = 130;
        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper =
            AptosWrapper::new(400, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let ledger_info_with_signature = aptos_wrapper.get_latest_li_bytes().unwrap();

        println!("Starting execution of signature verification...");
        let start = Instant::now();
        sig_execute(&ledger_info_with_signature).unwrap();
        println!("Execution took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_sig() {
        use super::*;
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use sphinx_sdk::ProverClient;
        use std::time::Instant;

        const NBR_VALIDATORS: usize = 130;
        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper =
            AptosWrapper::new(400, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let ledger_info_with_signature = aptos_wrapper.get_latest_li_bytes().unwrap();

        let client = ProverClient::new();

        let start = Instant::now();
        println!("Starting generation of signature verification proof...");
        let (proof, _) = sig_verification(&client, &ledger_info_with_signature).unwrap();
        println!("Proving took {:?}", start.elapsed());

        let (_, vk) = client.setup(aptos_programs::bench::SIGNATURE_VERIFICATION_PROGRAM);
        let start = Instant::now();
        println!("Starting verification of signature verification proof...");
        client.verify(&proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_snark_prove_sig() {
        use super::*;
        use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
        use sphinx_sdk::ProverClient;
        use std::time::Instant;

        setup_logger();

        const NBR_VALIDATORS: usize = 130;
        const AVERAGE_SIGNERS_NBR: usize = 95;

        let mut aptos_wrapper =
            AptosWrapper::new(400, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let ledger_info_with_signature = aptos_wrapper.get_latest_li_bytes().unwrap();

        let client = ProverClient::new();
        let (pk, vk) = client.setup(aptos_programs::bench::SIGNATURE_VERIFICATION_PROGRAM);

        let mut stdin = SphinxStdin::new();
        stdin.write(&ledger_info_with_signature);

        let start = Instant::now();
        println!("Starting generation of signature verification proof...");
        let snark_proof = client.prove_plonk(&pk, stdin).unwrap();
        println!("Proving took {:?}", start.elapsed());

        let start = Instant::now();
        println!("Starting verification of signature verification proof...");
        client.verify_plonk(&snark_proof, &vk).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
