use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::trusted_state::TrustedState;
use aptos_lc_core::NBR_VALIDATORS;
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use std::time::Duration;
use wp1_sdk::utils::setup_logger;
use wp1_sdk::{ProverClient, SP1Stdin};

// To run these benchmarks, first download `criterion` with `cargo install cargo-criterion`.
// Then `cargo criterion --bench ratchet`.
// For flamegraphs, run `cargo criterion --bench ratchet --features flamegraph -- --profile-time <secs>`.
// The results are located in `target/criterion/profile/<name-of-benchmark>`.
cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
          name = ratchet;
          config = Criterion::default().sample_size(10).warm_up_time(Duration::from_millis(3000)).with_profiler(pprof::criterion::PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
          targets = bench_ratchet
    }
  } else {
    criterion_group! {
          name = ratchet;
          config = Criterion::default().sample_size(10).warm_up_time(Duration::from_millis(3000));
          targets = bench_ratchet
    }
  }
}

criterion_main!(ratchet);

#[derive(Clone, Debug)]
struct ProvingAssets {
    trusted_state: Vec<u8>,
    validator_verifier_hash: Vec<u8>,
    epoch_change_proof: Vec<u8>,
}

const AVERAGE_SIGNERS_NBR: usize = 95;

impl ProvingAssets {
    fn new() -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR);

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier_hash = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash().to_vec(),
            _ => panic!("Expected epoch change for current trusted state"),
        };
        let trusted_state_version = *aptos_wrapper.current_version();

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let state_proof = aptos_wrapper.new_state_proof(trusted_state_version);

        let epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

        Self {
            trusted_state,
            validator_verifier_hash,
            epoch_change_proof: epoch_change_proof.clone(),
        }
    }

    fn prove(&self) {
        let mut stdin = SP1Stdin::new();

        setup_logger();

        stdin.write(&self.trusted_state);
        stdin.write(&self.epoch_change_proof);
        stdin.write(&self.validator_verifier_hash);

        let client = ProverClient::new();

        client
            .prove(aptos_programs::RATCHET_PROGRAM, stdin)
            .unwrap();
    }
}

fn bench_ratchet(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet-prod");
    group.sampling_mode(SamplingMode::Flat);

    let proving_assets = ProvingAssets::new();

    group.bench_function("RatchetExecute", |b| {
        b.iter(|| black_box(proving_assets.clone()).prove())
    });
}
