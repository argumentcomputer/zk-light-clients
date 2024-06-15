# Run the Client

The final components that we need to set up is the Client. As both the Aptos Full Node and the Proof Server are
available,
it will be able to start the coordinating the proving process between the two of them.

The first setup steps are similar to the Proof Server as they are binaries of te same crate.

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

## Launch the Client

With our deployment machine properly configured, we can run the client.

```bash
git clone git@github.com:lurk-lab/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  RUST_LOG="debug" cargo +nightly run -p proof-server --release --bin client -- --proof-server-address <PRIMARY_SERVER_ADDRESS> --aptos-node-url <APTOS_NODE_URL>
```

With this, the Client should start its initialization process and be able to make requests to both the Proof Server and
the Aptos Full Node.