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

When running any tests or benchmarks that makes Plonk proofs over BN254, the prover leverages some pre-built circuits
artifacts. Those circuits artifacts are generated when we release new versions of Sphinx and are made avaialble on a
remote storage. The current address for the storage can be
found [here](https://github.com/lurk-lab/sphinx/blob/dev/prover/src/install.rs).