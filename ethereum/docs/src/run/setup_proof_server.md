# Deploy the Proof Server

We have two components to deploy for the Proof Server to work as intended. The primary and the secondary server.
There is no particular order in which they should be deployed, but here we will deploy the secondary and then
the primary.

For best results, the primary and secondary servers should be deployed to **different server instances**, so that
proof generation can happen in parallel if necessary.

## Requirements

Make sure to finish the [initial configuration](./configuration.md) first.

## Environment variables

- `RUSTFLAGS="-C target-cpu=native -C opt-level=3"`:
    - `-C target-cpu=native`: This will ensure that the binary is optimized
      for the CPU it is running on. This is very important
      for [plonky3](https://github.com/plonky3/plonky3?tab=readme-ov-file#cpu-features) performance.
    - `-C opt-level=3`: This turns on the maximum level of compiler optimizations.
    - This can also be configured in `~/.cargo/config.toml` instead by adding:
        ```toml
        [target.'cfg(all())']
        rustflags = ["-C", "target-cpu=native", "-C", "opt-level=3"]
        ```

Make sure to launch the proof servers with `cargo +nightly-2024-05-31`.

> **Note**
>
> One can also set the `RUST_LOG` environment variable to `debug` to get more information
> about the execution of the server.

## Deploy the secondary server

Now that our deployment machine is properly configured, we can run the secondary server.

```bash
git clone git@github.com:lurk-lab/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  SHARD_SIZE=4194304 SHARD_BATCH_SIZE=0 RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3" cargo +nightly-2024-05-31 run --release --bin server_secondary -- -a <NETWORK_ADDRESS>
```

## Deploy the primary server

Finally, once the primary server is configured in the same fashion, run it:

```bash
git clone git@github.com:lurk-lab/zk-light-clients.git && \
  cd zk-light-clients/ethereum/light-client && \
  SHARD_SIZE=4194304 SHARD_BATCH_SIZE=0 RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo +nightly-2024-05-31 run --release --bin server_primary -- -a <NETWORK_ADDESS> --snd-addr <SECONDARY_SERVER_ADDRESS>
```
