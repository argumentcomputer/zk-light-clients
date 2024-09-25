use kadena_lc::proofs::longest_chain::{LongestChainIn, LongestChainProver};
use kadena_lc::proofs::{Prover, ProvingMode};
use kadena_lc_core::test_utils::get_layer_block_headers;
use kadena_lc_core::types::header::layer::ChainwebLayerHeader;
use serde::Serialize;
use std::env;
use std::time::Instant;

struct BenchmarkAssets {
    prover: LongestChainProver,
    layer_headers: Vec<ChainwebLayerHeader>,
}

impl BenchmarkAssets {
    fn generate() -> Self {
        let test_assets = get_layer_block_headers();

        Self {
            prover: LongestChainProver::new(),
            layer_headers: test_assets,
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

    let benchmark_assets = BenchmarkAssets::generate();

    let inputs = LongestChainIn::new(benchmark_assets.layer_headers.clone());

    // Generate proof
    let start_proving = Instant::now();
    let proof = benchmark_assets
        .prover
        .prove(&inputs, mode)
        .expect("Failed to prove longest chain");
    let proving_time = start_proving.elapsed();

    // Verify proof
    let start_verifying = Instant::now();
    benchmark_assets
        .prover
        .verify(&proof)
        .expect("Failed to verify longest chain proof");
    let verifying_time = start_verifying.elapsed();

    // Print results
    let results = BenchResults {
        proving_time: proving_time.as_millis(),
        verification_time: verifying_time.as_millis(),
    };

    println!("{}", serde_json::to_string(&results).unwrap());
}
