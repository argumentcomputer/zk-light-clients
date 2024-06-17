# Configuration

To run the Proof Server and the Client there are a few requirements that needs to be followed on the host machine.

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