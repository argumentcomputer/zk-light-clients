# Configuration

To run the Proof Server and the Client there are a few requirements that needs to be followed on the host machine.

First, you need to install nightly Rust and Golang. You can find the installation instructions for
Rust [here](https://www.rust-lang.org/tools/install) and for Golang [here](https://golang.org/doc/install).

Make sure to install **nightly** Rust, which is necessary for AVX-512 acceleration:

```bash
rustup default nightly
```

We pin the nightly Rust version in `rust-toolchain.toml` to prevent unknown future changes
to nightly from interfering with the build process. In principle however, any recent nightly release of Rust should
work.

Second, you need to install the `cargo-prove` binary.

1. Install `cargo-prove` from Sphinx:

```bash
git clone git@github.com:argumentcomputer/sphinx.git && \
    cd sphinx/cli && \
    cargo install --locked --path .
```

2. Install the toolchain. This downloads the pre-built toolchain from SP1

```bash
cd ~ && \
   cargo prove install-toolchain
```

3. Verify the installation by checking if `succinct` is present in the output of `rustup toolchain list`

Finally, there's a few extra packages needed for the build:

```bash
sudo apt update && sudo apt-get install -y build-essential libssl-dev pkg-config libudev-dev cmake
```

For non-Ubuntu/non-Debian based distros, make sure to install the equivalent packages.
