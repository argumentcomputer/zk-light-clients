# Configuration for the benchmarks

In this section we will cover the configuration that should be set to run the benchmarks. It is also
important to run the benchmarks on proper machines, such as the one described for the Proof Server in
the [Run the Light Client](../run/overview.md) section.

## Settings

Here are the standard config variables that are worth setting for any benchmark:

- `RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable"`
- `SHARD_SIZE=4194304`

  The highest possible setting, giving the fewest shards. Because the compression phase dominates the timing of the
  SNARK proofs, we need as few shards as possible.

- `SHARD_BATCH_SIZE=0`

  This disables checkpointing making proving faster at the expense of higher memory usage

- `cargo +nightly`

  This ensures you are on a nightly toolchain, overriding the local `rust-toolchain.toml` file. Nightly allows usage
  of AVX512 instructions which is crucial for performance.

- `cargo bench --release <...>`

  Or otherwise specify compiler options via `RUSTFLAGS="-Copt-level=3 lto=true <...>"` or Cargo profiles

- `RUST_LOG=debug` _(optional)_

  This prints out useful Sphinx metrics, such as cycle counts, iteration speed, proof size, etc.

## Requirements

The requirements to run the benchmarks are the same as the ones for the client. You can find those instructions
in [their dedicated section](../run/configuration.md).

## SNARK proofs

When running any tests or benchmarks that makes Plonk proofs over BN254, it's necessary to build the correct circuit artifacts.

If you don't manually build them, it will lead to a proof generation failure (unsatisfied constraint) due to
circuit differences between SP1 and Sphinx.

To enable Plonk proofs, we first need to generate the necessary circuit artifacts.

We need to head to the Sphinx repository and run the build script:

```bash
cd sphinx/prover && \
  make build-plonk-bn254 && \
  mkdir -p ~/.sp1/circuits/plonk_bn254/e48c01ec/ && \
  cp build/* ~/.sp1/circuits/plonk_bn254/e48c01ec/
```

The trailing commit identifier after `~/.sp1/circuits/plonk_bn254/` depends on the value of `PLONK_BN254_ARTIFACTS_COMMIT`
defined [here](https://github.com/lurk-lab/sphinx/blob/dev/prover/src/install.rs),
make sure to use the most up-to-date value for the specific Sphinx release.
