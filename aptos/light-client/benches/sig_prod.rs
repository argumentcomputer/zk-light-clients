use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::NBR_VALIDATORS;
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use std::time::Duration;
use wp1_sdk::utils::setup_logger;
use wp1_sdk::{ProverClient, SP1Stdin};

// To run these benchmarks, first download `criterion` with `cargo install cargo-criterion`.
// Then `cargo criterion --bench sig_prod`.
criterion_group! {
        name = sig;
        config = Criterion::default().sample_size(1).warm_up_time(Duration::from_millis(3000));
        targets = bench_sig
}

criterion_main!(sig);

#[derive(Clone, Debug)]
struct ProvingAssets {
    ledger_info_with_signature: Vec<u8>,
}

impl ProvingAssets {
    fn new() -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);
        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let ledger_info_with_signature = aptos_wrapper.get_latest_li_bytes().unwrap();

        Self {
            ledger_info_with_signature,
        }
    }

    fn prove(&self) {
        let mut stdin = SP1Stdin::new();

        setup_logger();

        stdin.write(&self.ledger_info_with_signature);

        let client = ProverClient::new();

        client
            .prove(aptos_programs::bench::SIGNATURE_VERIFICATION_PROGRAM, stdin)
            .unwrap();
    }
}

fn bench_sig(c: &mut Criterion) {
    let mut group = c.benchmark_group("sig-prod");
    group.sampling_mode(SamplingMode::Flat);

    let proving_assets = ProvingAssets::new();

    group.bench_function("SignatureVerificationProve", |b| {
        b.iter(|| black_box(proving_assets.clone()).prove())
    });
}
