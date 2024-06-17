# Deploy the Proof Server

As previously stated, we have two components to deploy for the Proof Server to work as intended. The primary and the
secondary server. There is no particular order in which they should be deployed, but here we will deploy the secondary
and then the primary.

## Requirements

Make sure that the configuration specified in [the dedicated section](./configuration.md) are met.

## SNARK proofs

We mentioned earlier that the Proof Server has the capabilities of handling two types of proofs: either Sphinx core proofs
or SNARK proofs using Plonk.

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

> **Note**
>
> One can also set the `RUST_LOG` environment variable to `debug` to get more information
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
