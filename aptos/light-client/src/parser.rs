use crate::error::LightClientError;
use wp1_sdk::utils::BabyBearPoseidon2;
use wp1_sdk::{SP1ProofWithIO, SP1Prover, SP1Stdin};

#[derive(Debug, Clone)]
pub struct ParsedBits {
    pub ledger_info: Vec<u8>,
    pub signature: Vec<u8>,
    pub validators_list: Vec<u8>,
    pub epoch: Vec<u8>,
}

#[allow(dead_code)]
fn parse_bits(
    ledger_info_with_signatures: Vec<u8>,
    nbr_validators: usize,
) -> Result<(SP1ProofWithIO<BabyBearPoseidon2>, ParsedBits), LightClientError> {
    #[cfg(debug_assertions)]
    {
        use wp1_sdk::utils;
        utils::setup_logger();
    }

    let mut stdin = SP1Stdin::new();

    stdin.write(&ledger_info_with_signatures);
    stdin.write(&nbr_validators);

    let mut proof =
        SP1Prover::prove(aptos_programs::BITS_PARSER_PROGRAM, stdin).map_err(|err| {
            LightClientError::ProvingError {
                program: "bits-parser".to_string(),
                source: err.into(),
            }
        })?;

    // Read output.
    let ledger_info_bits = proof.stdout.read::<Vec<u8>>();
    let signature_bits = proof.stdout.read::<Vec<u8>>();
    let validators_list_bits = proof.stdout.read::<Vec<u8>>();
    let epoch_bits = proof.stdout.read::<Vec<u8>>();

    Ok((
        proof,
        ParsedBits {
            ledger_info: ledger_info_bits,
            signature: signature_bits,
            validators_list: validators_list_bits,
            epoch: epoch_bits,
        },
    ))
}

#[cfg(test)]
mod test {
    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_parser() {
        use super::*;
        use std::time::Instant;
        use wp1_sdk::SP1Verifier;

        pub fn bytes_to_bits_le(bytes: &[u8]) -> Vec<u8> {
            bytes
                .iter()
                .flat_map(|&v| (0..8).map(move |i| (v >> i) & 1))
                .collect()
        }

        const NBR_VALIDATORS: usize = 10;

        // Generate LedgerInfoWithSignatures
        let mut aptos_wrapper =
            aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper::new(4, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let ledger_info_with_signatures_bits =
            bytes_to_bits_le(&aptos_wrapper.get_latest_li_bytes().unwrap());
        let ledger_info_with_signatures = aptos_wrapper.get_latest_li().unwrap();

        // Parse bits
        let start = Instant::now();
        println!("Starting generation of bytes parser proof...");
        let (proof, parsed_bits) =
            parse_bits(ledger_info_with_signatures_bits, NBR_VALIDATORS).unwrap();
        println!("Proving took {:?}", start.elapsed());

        // Test extraction
        let ledger_info_bits = bytes_to_bits_le(
            &bcs::to_bytes(ledger_info_with_signatures.ledger_info())
                .expect("ledger info serialization failed"),
        );
        assert_eq!(parsed_bits.ledger_info, ledger_info_bits);

        let signature_bits = bytes_to_bits_le(
            &bcs::to_bytes(ledger_info_with_signatures.signatures())
                .expect("signature serialization failed"),
        );
        assert_eq!(parsed_bits.signature, signature_bits);

        let validators_list_bits = bytes_to_bits_le(
            &bcs::to_bytes(
                &ledger_info_with_signatures
                    .ledger_info()
                    .next_epoch_state()
                    .unwrap()
                    .verifier,
            )
            .expect("validators serialization failed"),
        );
        assert_eq!(parsed_bits.validators_list, validators_list_bits);

        let epoch_bits = bytes_to_bits_le(
            &bcs::to_bytes(&ledger_info_with_signatures.ledger_info().epoch())
                .expect("epoch serialization failed"),
        );
        assert_eq!(parsed_bits.epoch, epoch_bits);

        let start = Instant::now();
        println!("Starting verification of bytes parser proof...");
        SP1Verifier::verify(aptos_programs::BITS_PARSER_PROGRAM, &proof).unwrap();
        println!("Verification took {:?}", start.elapsed());
    }
}
