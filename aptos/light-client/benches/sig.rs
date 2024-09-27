// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use std::env;
use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use serde::Serialize;
use sphinx_sdk::utils::setup_logger;
use sphinx_sdk::{ProverClient, SphinxProofWithPublicValues, SphinxStdin};
use std::hint::black_box;
use std::time::Instant;
use anyhow::anyhow;

const NBR_VALIDATORS: usize = 130;

struct ProvingAssets {
    mode: ProvingMode,
    client: ProverClient,
    ledger_info_with_signature: Vec<u8>,
}


#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProvingMode {
    STARK,
    SNARK,
}


impl From<ProvingMode> for String {
    fn from(mode: ProvingMode) -> String {
        match mode {
            ProvingMode::STARK => "STARK".to_string(),
            ProvingMode::SNARK => "SNARK".to_string(),
        }
    }
}

impl TryFrom<&str> for ProvingMode {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "STARK" => Ok(ProvingMode::STARK),
            "SNARK" => Ok(ProvingMode::SNARK),
            _ => Err(anyhow!("Invalid proving mode")),
        }
    }
}


impl ProvingAssets {
    fn new(mode: ProvingMode) -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS).unwrap();
        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let ledger_info_with_signature = aptos_wrapper.get_latest_li_bytes().unwrap();

        let client = ProverClient::new();

        Self {
            mode,
            client,
            ledger_info_with_signature,
        }
    }

    fn prove(&self) -> SphinxProofWithPublicValues {
        let mut stdin = SphinxStdin::new();

        setup_logger();

        stdin.write(&self.ledger_info_with_signature);

        let (pk, _) = self
            .client
            .setup(aptos_programs::bench::SIGNATURE_VERIFICATION_PROGRAM);

        match self.mode {
            ProvingMode::STARK => self.client.prove(&pk, stdin).run().unwrap(),
            ProvingMode::SNARK => self.client.prove(&pk, stdin).plonk().run().unwrap(),
        }
    }

    fn verify(&self, proof: &SphinxProofWithPublicValues) {
        let (_, vk) = self
            .client
            .setup(aptos_programs::bench::SIGNATURE_VERIFICATION_PROGRAM);
        self.client.verify(proof, &vk).expect("Verification failed");
    }
}

#[derive(Serialize)]
struct Timings {
    proving_time: u128,
    verifying_time: u128,
}

fn main() {
    let mode_str: String = env::var("MODE").unwrap_or_else(|_| "STARK".into());
    let mode = ProvingMode::try_from(mode_str.as_str()).expect("MODE should be STARK or SNARK");

    let proving_assets = ProvingAssets::new(mode);

    let start_proving = Instant::now();
    let proof = proving_assets.prove();
    let proving_time = start_proving.elapsed();

    let start_verifying = Instant::now();
    proving_assets.verify(black_box(&proof));
    let verifying_time = start_verifying.elapsed();

    // Print results in JSON format.
    let timings = Timings {
        proving_time: proving_time.as_millis(),
        verifying_time: verifying_time.as_millis(),
    };

    let json_output = serde_json::to_string(&timings).unwrap();
    println!("{}", json_output);
}
