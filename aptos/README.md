## Aptos Light Client

This is a light client for the Aptos blockchain. It is written in Rust and lives in the workspace defined in this
directory.
In this README we will go over a few details that need to be known before hopping into development.

> [!NOTE]
> A dive in the Light Client design and the available programs can be found on
> HackMD: https://hackmd.io/@lurk-lab/HJvnlbKGR

## Layout

The workspace is divided into the following:

- `light-client`: The main library that contains the light client implementation. It is in charge of producing proofs
  regarding the consensus of the chain and inclusion of some account values in a Merkle Tree.
- `core`: The core library that contains the data structures and utilities used by the light client.
- `aptos-programs`: A library that exposes the Sphinx programs used to generate proofs for our light client.*
- `programs/*`: Actual implementations of the Sphinx programs.

## Development

When developing, you might have to update the programs' implementation. The
programs implementations are located in `./programs/*` and the compiled binaries
are located in `./aptos-programs/artifacts`. Currently, artifacts binaries are
generated in two ways:

- Automated: There is a build script located at `./aptos-programs/build.rs` that
  will compile all the programs and place them in the `./aptos-programs/artifacts`
  folder.
- Manual: You can also compile the programs manually using `make` by running the following
  command in the `./aptos-programs` folder:
  ```shell
    make
    ```

## Benchmarks

The benchmarks for our various programs are located in the `light-client` crate folder.

Benchmarks can be classified in two distinct categories:

- _end-to-end_: Those benchmarks are associated with programs that are meant to reproduce
  a production environment settings. They are meant to measure performance for a complete
  end-to-end flow.
- _internals_: Those benchmarks are associated with programs that are solely meant for
  performance measurements on specific parts of the codebase. They are
  not meant to measure performance for, or reproduce a production environment settings.

  ### End-to-end

- `e2e`: Benchmark that will run a proof generation for the programs contained
  in `programs/ratchet/src/main.rs` and `programs/merkle/src/main.rs`. The goal here
  is to test the complete flow for our light client and get cycle count and proving
  time for it.
- `epoch_change`: Benchmark that will run a proof generation for the program contained
  in `programs/epoch-change/src/main.rs`. This program will execute a hash for the received
  `ValidatorVerifier` to ensure that the signature is from the previous validator set,
  execute a `TrustedState::verify_and_ratchet_inner` and finally generate the
  hash for the verified `ValidatorVerifier`.
- `inclusion`: Benchmark that will run a proof generation for the program contained
  in `programs/inclusion/src/main.rs`. It is meant to assess the cost of verifying
  a Merkle proof for a given leaf and a given root.

### Internals

- `sig: Benchmark that will run a proof generation for the program contained
  in `programs/benchmarks/signature-verification/src/main.rs`. This program mainly executes
  an aggregated signature verification for an aggregated signature and a set
  of public keys.
- `bytes`: Benchmark that will run a proof generation for the program contained
  in `programs/benchmarks/bytes/src/main.rs`. It is meant to assess the cost of serializing
  and deserializing data structures of interest to us.

The benchmark that is the closest to a production scenario is `e2e`. Most of
the other benchmarks are more specific and are meant to assess the cost
of specific operations.

### Requirements

To run the benchmarks, you will have to install `cargo criterion`. You can do
so by downloading it with `cargo install cargo-criterion`.

You will also need to install `pkg-config` and `libudev-dev`. On Linux, you can run:

```shell
sudo apt-get update && sudo apt-get install -y pkg-config libudev-dev
```

### Installing zkvm toolchain and WP1's `cargo-prove`

These are slightly modified instructions from
the [SP1 install from source](https://succinctlabs.github.io/sp1/getting-started/install.html#option-2-building-from-source)
manual.

**It's important to install `cargo-prove` from Sphinx since it includes compiler optimization flags not present in SP1.**

1. Ensure that the `cargo-prove` binary from SP1 is not installed, and if it is, remove it from `PATH`.
2. Install `cargo-prove` from WP1:

   git clone git@github.com:wormhole-foundation/wp1.git
   cd wp1/cli
   cargo install --locked --path .

3. Install the toolchain. This downloads the pre-built toolchain from SP1

   cd ~
   cargo prove install-toolchain

4. Verify the installation by checking if `succinct` is present in the output of `rustup toolchain list`

### Running the benchmarks

**Using Makefile**

To ease benchmark run we created a Makefile in the `light-client` crate folder.
Just run:

```shell
make benchmark
```

You will then be asked for the name of the benchmark you want to run. Just
fill in the one that is of interest to you:

```shell
$ make benchmark
Enter benchmark name: e2e

  ...
  
```

**Manual**

For a manual run, it is necessary to set some Rust environments variable as
such:

- `RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable"`:
    - `-C target-cpu=native`: This will ensure that the binary is optimized
      for the CPU it is running on. This is very important
      for [plonky3](https://github.com/plonky3/plonky3?tab=readme-ov-file#cpu-features) performance.
    - `--cfg tokio_unstable`: This will enable the unstable features of the
      Tokio runtime. This is necessary for aptos dependencies.
    - This can also be configured in `~/.cargo/config.toml` instead by adding:
        ```toml
        [target.'cfg(all())']
        rustflags = ["--cfg", "tokio_unstable", "-C", "target-cpu=native"]
        ```

- `RUST_LOG="debug"`: This will enable the debug logs for the benchmark run, allowing you
  to access the cycle tracking numbers for the program execution.
- **Use nightly rust on an AVX-512 equipped CPU for optimal performance.**

Then, move to the `light-client` folder and run the following command:

```shell
cargo +nightly bench --features aptos --bench execute -- <benchmark_name>
```

### Interpreting the results

Before delving into the details, please take a look at the [cycle tracking documentation
from SP1](https://succinctlabs.github.io/sp1/writing-programs/cycle-tracking.html) to get a rough sense of what the
numbers mean.

The benchmark will output a lot of information. The most important parts are the
following:

**Total cycles for the program execution**

This value can be found on the following line:

```shell
INFO summary: cycles=63736, e2e=2506, khz=25.43, proofSize=2.66 MiB
```

It contains the total number of cycles needed for the program, the end-to-end time in milliseconds, the frequency of the
CPU in kHz, and the size of the proof generated.

**Specific cycle count**

In the output, you will find a section that looks like this:

```shell
DEBUG ┌╴read_inputs    
DEBUG └╴9,553 cycles    
DEBUG ┌╴verify_merkle_proof    
DEBUG └╴40,398 cycles    
```

These specific cycles count are generated by us to track the cost of specific operations in the program.

**Proving time**
The proving time can be found through the output of the `criterion` crate.
They have the following shape:

```shell
WP1-Verifying/NbrSiblings/17                                                                          
                        time:   [765.63 ms 770.67 ms 776.32 ms]
```

### Alternative

As the benchmark can take a long time to run thanks to criterion having a number of
required run at 10, you can also run the tests located in the `light-client`
crate. They will output the same logs as the benchmarks, only the time necessary
to generate a proof will change shape:

```shell
Starting generation of Merkle inclusion proof with 18 siblings...
Proving locally
Proving took 5.358508094s
Starting verification of Merkle inclusion proof...
Verification took 805.530068ms
```

To run the test efficiently, first install `nextest` following [its documentation](https://nexte.st/book/installation).
Ensure that you also have the previously described environment variables set, then run the following command:

```shell
cargo +nightly nextest run --verbose --release --profile ci --features aptos --package aptos-lc --no-capture
```

> Note: The `--no-capture` flag is necessary to see the logs generated by the tests.