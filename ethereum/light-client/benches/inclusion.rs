// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use ethereum_lc::proofs::inclusion::{StorageInclusionIn, StorageInclusionProver};
use ethereum_lc::proofs::{Prover, ProvingMode};
use ethereum_lc::types::storage::GetProofResponse;
use ethereum_lc_core::merkle::storage_proofs::EIP1186Proof;
use ethereum_lc_core::types::bootstrap::Bootstrap;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::{FinalityUpdate, Update};
use serde::Serialize;
use std::env::current_dir;
use std::time::Instant;
use std::{env, fs};

struct BenchmarkAssets {
    prover: StorageInclusionProver,
    store: LightClientStore,
    finality_update: FinalityUpdate,
    eip1186_proof: EIP1186Proof,
}

impl BenchmarkAssets {
    fn generate() -> BenchmarkAssets {
        // Instantiate bootstrap data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/inclusion/LightClientBootstrapDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate Update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/inclusion/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate finality update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/inclusion/LightClientFinalityUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let finality_update = FinalityUpdate::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate EIP1186 proof data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/inclusion/base-data/EthGetProof.json");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let ethers_eip1186_proof: GetProofResponse = serde_json::from_slice(&test_bytes).unwrap();

        // Initialize the LightClientStore
        let checkpoint = "0xf783c545d2dd90cee6c4cb92a9324323ef397f6ec85e1a3d61c48cf6cfc979e2";
        let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

        store.process_light_client_update(&update).unwrap();

        let prover = StorageInclusionProver::new();

        BenchmarkAssets {
            prover,
            store,
            finality_update,
            eip1186_proof: EIP1186Proof::try_from(ethers_eip1186_proof.result().clone()).unwrap(),
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
    let benchmark_assets = BenchmarkAssets::generate();

    // Prove storage inclusion
    let inputs = StorageInclusionIn::new(
        benchmark_assets.store,
        benchmark_assets.finality_update.into(),
        benchmark_assets.eip1186_proof,
    );

    let start_proving = Instant::now();
    let proof = benchmark_assets
        .prover
        .prove(&inputs, mode)
        .expect("Failed to prove storage inclusion");
    let proving_time = start_proving.elapsed();

    // Verify proof
    let start_verifying = Instant::now();
    benchmark_assets
        .prover
        .verify(&proof)
        .expect("Failed to verify storage inclusion proof");
    let verifying_time = start_verifying.elapsed();

    // Print results
    let results = BenchResults {
        proving_time: proving_time.as_millis(),
        verification_time: verifying_time.as_millis(),
    };

    let json_output = serde_json::to_string(&results).unwrap();
    println!("{}", json_output);
}
