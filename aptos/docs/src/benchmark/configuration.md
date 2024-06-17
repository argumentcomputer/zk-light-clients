# Configuration for the benchmarks

In this section we will cover the configuration that should be set to run the benchmarks. It is also
important to run the benchmarks on proper machines, such as the one described for the Proof Server in
the [Run the Light Client](../run/overview.md) section.

## Settings

Here are the standard config variables that are worth setting for any benchmark:

- `RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable"`
- `SHARD_SIZE=4194304`

  The highest possible setting, giving the fewest shards. Because the compression phase dominates the timing of the
  groth16 proofs, we need as few shards as possible.

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

There are a few requirements for the Proof Server to work.

First, you need to install Rust and Golang. You can find the installation instructions for
Rust [here](https://www.rust-lang.org/tools/install) and for Golang [here](https://golang.org/doc/install).

Second, you need to install the `cargo-prove` binary.

1. Install `cargo-prove` from Sphinx:

```bash
git clone git@github.com:lurk-lab/sphinx.git && \
    cd sphinx/cli && \
    cargo install --locked --path .
```

2. Install the toolchain. This downloads the pre-built toolchain from SP1

```bash
cd ~ && \
   cargo prove install-toolchain
```

3. Verify the installation by checking if `succinct` is present in the output of `rustup toolchain list`

Finally, there a few packages needed for the build to properly work:

```bash
sudo apt update && sudo apt-get install -y pkg-config libudev-dev
```

## Groth16 proofs

When running any tests or benchmarks that makes Groth16 proofs, it's necessary to build the correct circuit artifacts.

Currently, if you don't manually build them, it will lead to a proof generation failure (unsatisfied constraint) due to
circuit differences.

To build the Groth16 artifacts, do the following:

```shell
unset FRI_QUERIES && \
  cd sphinx/prover && \
  make build-groth16 && \
  mkdir -p ~/.sp1/circuits/groth16/9f43e920/ && \
  cp build/* ~/.sp1/circuits/groth16/9f43e920/
```

The trailing commit identifier after `~/.sp1/circuits/groth16/` depends on the value of `GROTH16_ARTIFACTS_COMMIT`
defined [here](https://github.com/lurk-lab/sphinx/blob/dev/prover/src/install.rs),
make sure to use the most up-to-date value.