# Deploy the Proof Server

As previously stated, we have two components to deploy for the Proof Server to work as intended. The primary and the
secondary server. There is no particular order in which they should be deployed, but here we will deploy the secondary
and then the primary.

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
sudo apt update && sudo apt-get install -y build-essential libssl-dev pkg-config libudev-dev cmake
```

## Groth16 proofs

We mentioned earlier that the Proof Server has the capabilities of handling two types of proofs: either SP1 core proofs
or Groth16 proofs.

To enable Groth16 proofs, we first need to generate the necessary circuit artifacts.

We need to head to the Sphinx repository and run the build script:

```bash
cd sphinx/prover && \
  make build-groth16 && \
  mkdir -p ~/.sp1/circuits/groth16/9f43e920/ && \
  cp build/* ~/.sp1/circuits/groth16/9f43e920/
```

The trailing commit identifier after `~/.sp1/circuits/groth16/` depends on the value of `GROTH16_ARTIFACTS_COMMIT`
defined [here](https://github.com/lurk-lab/sphinx/blob/3f60558d3465c51d7261c33aa8e63d7c7356ca25/prover/src/install.rs#L13),
make sure to use the most up-to-date value.

## Environment variables

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

> Note: It can also prove interesting to set the `RUST_LOG` environment variable to `debug` to get more information
> about the execution of the server.

## Deploy the secondary server

Now that our deployment machine is properly configured, we can run the secondary server.

```bash
git clone git@github.com:lurk-lab/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable" cargo +nightly run --release --bin server_secondary -- -a <NETWORK_ADDRESS>
```

## Deploy the primary server

Finally, once the primary server is configured in the same fashion, run it:

```bash
git clone git@github.com:lurk-lab/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable" cargo +nightly run --release --bin server_primary -- -a <NETWORK_ADDESS> --snd-addr <SECONDARY_SERVER_ADDRESS>
```