use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::merkle::proof::SparseMerkleProof;
use aptos_lc_core::NBR_VALIDATORS;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use std::time::Duration;
use wp1_sdk::utils::{setup_logger, BabyBearPoseidon2};
use wp1_sdk::{ProverClient, SP1ProofWithIO, SP1Stdin};

const NBR_LEAVES: [usize; 5] = [32, 128, 2048, 8192, 32768];

// To run these benchmarks, first download `criterion` with `cargo install cargo-criterion`.
// Then `cargo criterion --bench merkle`.
// For flamegraphs, run `cargo criterion --bench merkle --features flamegraph -- --profile-time <secs>`.
// The results are located in `target/criterion/profile/<name-of-benchmark>`.
cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
          name = merkle;
          config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof::criterion::PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
          targets = bench_merkle
    }
  } else {
    criterion_group! {
          name = merkle;
          config = Criterion::default().warm_up_time(Duration::from_millis(3000));
          targets = bench_merkle
    }
  }
}

criterion_main!(merkle);

struct ProvingAssets {
    client: ProverClient,
    sparse_merkle_proof: SparseMerkleProof,
    leaf_key: [u8; 32],
    leaf_value: [u8; 32],
    expected_root: [u8; 32],
}

impl ProvingAssets {
    fn from_nbr_leaves(nbr_leaves: usize) -> Self {
        let mut aptos_wrapper = AptosWrapper::new(nbr_leaves, NBR_VALIDATORS, NBR_VALIDATORS);
        aptos_wrapper.generate_traffic();

        let proof_assets = aptos_wrapper
            .get_latest_proof_account(nbr_leaves - 1)
            .unwrap();

        let sparse_merkle_proof: SparseMerkleProof =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.state_proof()).unwrap()).unwrap();
        let leaf_key: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.key()).unwrap()).unwrap();
        let expected_root: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.root_hash()).unwrap()).unwrap();
        let leaf_value: [u8; 32] =
            bcs::from_bytes(&bcs::to_bytes(&proof_assets.state_value_hash()).unwrap()).unwrap();

        let client = ProverClient::new();

        Self {
            client,
            sparse_merkle_proof,
            leaf_value,
            leaf_key,
            expected_root,
        }
    }

    fn prove(&self) -> SP1ProofWithIO<BabyBearPoseidon2> {
        let mut stdin = SP1Stdin::new();

        stdin.write(&self.sparse_merkle_proof);
        stdin.write(&self.leaf_key);
        stdin.write(&self.leaf_value);
        stdin.write(&self.expected_root);

        self.client
            .prove(aptos_programs::MERKLE_PROGRAM, stdin)
            .unwrap()
    }

    fn verify(&self, proof: &SP1ProofWithIO<BabyBearPoseidon2>) {
        self.client
            .verify(aptos_programs::MERKLE_PROGRAM, proof)
            .expect("Verification failed");
    }
}

fn bench_merkle(c: &mut Criterion) {
    for nbr_leaves in NBR_LEAVES {
        let proving_assets = ProvingAssets::from_nbr_leaves(nbr_leaves);

        let mut wp1_proving_group = c.benchmark_group("WP1-Proving");
        wp1_proving_group
            .sampling_mode(SamplingMode::Flat)
            .sample_size(1);

        setup_logger();

        wp1_proving_group.bench_with_input(
            BenchmarkId::new(
                "NbrSiblings",
                proving_assets.sparse_merkle_proof.siblings().len(),
            ),
            &proving_assets.sparse_merkle_proof.siblings().len(),
            |b, _| b.iter(|| proving_assets.prove()),
        );

        wp1_proving_group.finish();

        let proof = proving_assets.prove();

        let mut wp1_verifying_group = c.benchmark_group("WP1-Verifying");
        wp1_verifying_group
            .sampling_mode(SamplingMode::Auto)
            .sample_size(10);

        wp1_verifying_group.bench_with_input(
            BenchmarkId::new(
                "NbrSiblings",
                proving_assets.sparse_merkle_proof.siblings().len(),
            ),
            &proving_assets.sparse_merkle_proof.siblings().len(),
            |b, _| b.iter(|| proving_assets.verify(black_box(&proof))),
        );

        wp1_verifying_group.finish();
    }
}
