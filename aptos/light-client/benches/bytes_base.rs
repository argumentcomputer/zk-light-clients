use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::NBR_VALIDATORS;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use std::time::Duration;
use wp1_sdk::utils::{setup_logger, BabyBearPoseidon2};
use wp1_sdk::{ProverClient, SP1ProofWithIO, SP1Stdin};

// To run these benchmarks, first download `criterion` with `cargo install cargo-criterion`.
// Then `cargo criterion --bench bytes_base`.
criterion_group! {
        name = bytes;
        config = Criterion::default().warm_up_time(Duration::from_millis(3000));
        targets = bench_bytes
}

criterion_main!(bytes);

struct ProvingAssets {
    client: ProverClient,
    ledger_info_with_signature: Vec<u8>,
}

impl ProvingAssets {
    fn new() -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);
        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let ledger_info_with_signature = aptos_wrapper.get_latest_li_bytes().unwrap();

        let client = ProverClient::new();

        Self {
            client,
            ledger_info_with_signature,
        }
    }

    fn prove(&self) -> SP1ProofWithIO<BabyBearPoseidon2> {
        let mut stdin = SP1Stdin::new();

        setup_logger();

        stdin.write(&self.ledger_info_with_signature);

        self.client
            .prove(aptos_programs::bench::BYTES, stdin)
            .unwrap()
    }

    fn verify(&self, proof: &SP1ProofWithIO<BabyBearPoseidon2>) {
        self.client
            .verify(aptos_programs::bench::BYTES, proof)
            .expect("Verification failed");
    }
}

fn bench_bytes(c: &mut Criterion) {
    let proving_assets = ProvingAssets::new();

    setup_logger();

    let mut wp1_proving_group = c.benchmark_group("WP1-Proving");
    wp1_proving_group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(1);

    setup_logger();

    wp1_proving_group.bench_with_input(
        BenchmarkId::new("BytesSize", proving_assets.ledger_info_with_signature.len()),
        &proving_assets.ledger_info_with_signature.len(),
        |b, _| b.iter(|| proving_assets.prove()),
    );

    wp1_proving_group.finish();

    let proof = proving_assets.prove();

    let mut wp1_verifying_group = c.benchmark_group("WP1-Verifying");
    wp1_verifying_group
        .sampling_mode(SamplingMode::Auto)
        .sample_size(10);

    wp1_verifying_group.bench_with_input(
        BenchmarkId::new("BytesSize", proving_assets.ledger_info_with_signature.len()),
        &proving_assets.ledger_info_with_signature.len(),
        |b, _| b.iter(|| proving_assets.verify(black_box(&proof))),
    );

    wp1_verifying_group.finish();
}
