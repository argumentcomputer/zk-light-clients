# Deploy the Proof Server

> **Note**
>
> We will deploy the server as through the execution of the binary with `cargo` in this example.
> It is also possible to deploy the proof server through its docker image. To do so, please
> refer to [the dedicated documentation](https://github.com/argumentcomputer/zk-light-clients/tree/dev/docker).

For the Proof Server, we have to take into account that generating a proof is a heavy operation. To avoid
overloading the server, we can split the proof generation into two servers. The primary server will handle
inclusion proofs, and the secondary server will handle epoch change proofs.

For best results, the primary and secondary servers should be deployed to **different server instances**, so that
proof generation can happen in parallel if necessary.

## Requirements

Make sure to finish the [initial configuration](./configuration.md) first.

## Environment variables

- `RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3"`:
    - `-C target-cpu=native`: This will ensure that the binary is optimized
      for the CPU it is running on. This is very important
      for [plonky3](https://github.com/plonky3/plonky3?tab=readme-ov-file#cpu-features) performance.
    - `--cfg tokio_unstable`: This will enable the unstable features of the
      Tokio runtime. This is necessary for aptos dependencies.
    - `-C opt-level=3`: This turns on the maximum level of compiler optimizations.
    - This can also be configured in `~/.cargo/config.toml` instead by adding:
        ```toml
        [target.'cfg(all())']
        rustflags = ["--cfg", "tokio_unstable", "-C", "target-cpu=native", "-C", "opt-level=3"]
        ```

> **Note**
>
> One can also set the `RUST_LOG` environment variable to `debug` to get more information
> about the execution of the server.

## Deploy the secondary server

Now that our deployment machine is properly configured, we can run the secondary server.

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  SHARD_BATCH_SIZE=0 RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3" cargo run --release --bin proof_server -- --mode "single" -a <NETWORK_ADDRESS>
```

## Deploy the primary server

Finally, once the primary server is configured in the same fashion, run it:

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  SHARD_BATCH_SIZE=0 RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3" cargo run --release --bin proof_server -- --mode "split" -a <NETWORK_ADDESS> --snd-addr <SECONDARY_SERVER_ADDRESS>
```

> **Note**
>
> Logging can be configured via `RUST_LOG` for Rust logging and `SP1_GO_LOG` for Go FFI logging.
> For example: `RUST_LOG=debug SP1_GO_LOG=debug cargo run ...`
> See the [configuration documentation](./configuration.md#logging-configuration) for more details.
