# Deploy the Proof Server

We have two components to deploy for the Proof Server to work as intended. The primary and the secondary server.
There is no particular order in which they should be deployed, but here we will deploy the secondary and then
the primary.

For best results, the primary and secondary servers should be deployed to **different server instances**, so that
proof generation can happen in parallel if necessary.

## Requirements

Make sure to finish the [initial configuration](./configuration.md) first.

## Environment variables

The environment variables to set for the Proof Server are explained in [the following
section](../benchmark/configuration.md).

> **Note**
>
> One can also set the `RUST_LOG` environment variable to `debug` to get more information
> about the execution of the server.

## Deploy the secondary server

Now that our deployment machine is properly configured, we can run the secondary server.

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/kadena/light-client && \
  RECONSTRUCT_COMMITMENTS=false SHARD_BATCH_SIZE=0 SHARD_CHUNKING_MULTIPLIER=64 SHARD_SIZE=4194304 RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo run --release --bin proof_server -- --mode "single" -a <NETWORK_ADDRESS>
```

## Deploy the primary server

Finally, once the primary server is configured in the same fashion, run it:

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/kadena/light-client && \
  RECONSTRUCT_COMMITMENTS=false SHARD_BATCH_SIZE=0 SHARD_CHUNKING_MULTIPLIER=64 SHARD_SIZE=4194304 RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo run --release --bin proof_server -- --mode "split" -a <NETWORK_ADDESS> --snd-addr <SECONDARY_SERVER_ADDRESS>
```
