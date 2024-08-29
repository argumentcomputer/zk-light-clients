# Configuration for the benchmarks

In this section we will cover the configuration that should be set to run the benchmarks. It is also
important to run the benchmarks on proper machines, such as the one described for the Proof Server in
the [Run the Light Client](../run/overview.md) section.

## Requirements

The requirements to run the benchmarks are the same as the ones for the client. You will need to follow
the instructions listed [here](../run/configuration.md).

## Other settings

Here are the standard config variables that are worth setting for any benchmark:

- `RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3"`

  This can also be configured in `~/.cargo/config.toml` by adding:
    ```toml
    [target.'cfg(all())']
    rustflags = ["--cfg", "tokio_unstable", "-C", "target-cpu=native", "-C", "opt-level=3"]
    ```

- `SHARD_SIZE=4194304` (for SNARK), `SHARD_SIZE=1048576` (for STARK)

  The highest possible setting, giving the fewest shards. Because the compression phase dominates the timing of the
  SNARK proofs, we need as few shards as possible.

- `SHARD_BATCH_SIZE=0`

  This disables checkpointing making proving faster at the expense of higher memory usage

- `RECONSTRUCT_COMMITMENTS=false`

  This setting enables keeping the FFT's data and the entire Merkle Tree in memory without necessity to recompute them
  in every shard.

- `SHARD_CHUNKING_MULTIPLIER=32` (for SNARK), `SHARD_CHUNKING_MULTIPLIER=1` (for STARK)

  This settings is usually selected depending on specific hardware where proving is executed. It is used to determine
- how many shards get chunked per core on the CPU. For STARK

- `cargo bench --release <...>`

  Make sure to always run in release mode with `--release`. Alternatively, specify the proper compiler options via
  `RUSTFLAGS="-C opt-level=3 <...>"`, `~/.cargo/config.toml` or Cargo profiles

- `RUST_LOG=debug` _(optional)_

  This prints out useful Sphinx metrics, such as cycle counts, iteration speed, proof size, etc. NOTE: This may cause a significant performance degradation, and is only recommended for collecting metrics other than wall clock time.

## SNARK proofs

When running any tests or benchmarks that makes Plonk proofs over BN254, the prover leverages some pre-built circuits
artifacts. Those circuits artifacts are generated when we release new versions of Sphinx and are automatically
downloaded on first use. The current address for downloading the artifacts can be found
[here](https://github.com/argumentcomputer/sphinx/blob/dev/prover/src/install.rs), but it should not be necessary to download
them manually.
