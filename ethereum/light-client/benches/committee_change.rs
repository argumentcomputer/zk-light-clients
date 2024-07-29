// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use ethereum_lc::proofs::committee_change::{CommitteeChangeIn, CommitteeChangeProver};
use ethereum_lc::proofs::{Prover, ProvingMode};
use ethereum_lc_core::types::bootstrap::Bootstrap;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::Update;
use serde::Serialize;
use std::env::current_dir;
use std::time::Instant;
use std::{env, fs};

struct BenchmarkAssets {
    prover: CommitteeChangeProver,
    store: LightClientStore,
    update: Update,
    update_new_period: Update,
}

impl BenchmarkAssets {
    fn generate() -> BenchmarkAssets {
        // Instantiate bootstrap data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/LightClientBootstrapDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate Update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate new period Update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/LightClientUpdateNewPeriodDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update_new_period = Update::from_ssz_bytes(&test_bytes).unwrap();

        // Initialize the LightClientStore
        let checkpoint = "0xefb4338d596b9d335b2da176dc85ee97469fc80c7e2d35b9b9c1558b4602077a";
        let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        let store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

        let prover = CommitteeChangeProver::new();

        BenchmarkAssets {
            prover,
            store,
            update,
            update_new_period,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct BenchResults {
    proving_time: u128,
    verification_time: u128,
}

fn main() {
    let mode_str: String = env::var("MODE").unwrap_or_else(|_| "STARK".into());
    let mode = ProvingMode::try_from(mode_str.as_str()).expect("MODE should be STARK or SNARK");

    // Instantiate BenchmarkAssets
    let mut benchmark_assets = BenchmarkAssets::generate();

    // Set next committee
    benchmark_assets
        .store
        .process_light_client_update(&benchmark_assets.update)
        .unwrap();

    // Prove committee change
    let inputs = CommitteeChangeIn::new(benchmark_assets.store, benchmark_assets.update_new_period);

    let start_proving = Instant::now();
    let proof = benchmark_assets
        .prover
        .prove(inputs, mode)
        .expect("Failed to prove committee change");
    let proving_time = start_proving.elapsed();

    // Verify proof
    let start_verifying = Instant::now();
    benchmark_assets
        .prover
        .verify(&proof)
        .expect("Failed to verify committee change proof");
    let verifying_time = start_verifying.elapsed();

    // Print results
    let results = BenchResults {
        proving_time: proving_time.as_millis(),
        verification_time: verifying_time.as_millis(),
    };

    let json_output = serde_json::to_string(&results).unwrap();
    println!("{}", json_output);
}
