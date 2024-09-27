# Deploy the Proof Server

> **Note**
>
> We will deploy the server as through the execution of the bianry with `cargo` in this example.
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

For more details onthe optimal environment variables to set to run the Proof Server,
please refer [to our dedicated documentation](../benchmark/configuration.md).

> **Note**
>
> One can also set the `RUST_LOG` environment variable to `debug` to get more information
> about the execution of the server.

## Deploy the secondary server

Now that our deployment machine is properly configured, we can run the secondary server.

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/ethereum/light-client && \
  RECONSTRUCT_COMMITMENTS=false SHARD_BATCH_SIZE=0 SHARD_CHUNKING_MULTIPLIER=64 SHARD_SIZE=4194304 RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo run --release --bin proof_server -- --mode "single" -a <NETWORK_ADDRESS>
```

## Deploy the primary server

Finally, once the primary server is configured in the same fashion, run it:

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/ethereum/light-client && \
  RECONSTRUCT_COMMITMENTS=false SHARD_BATCH_SIZE=0 SHARD_CHUNKING_MULTIPLIER=64 SHARD_SIZE=4194304 RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo run --release --bin proof_server -- --mode "split" -a <NETWORK_ADDESS> --snd-addr <SECONDARY_SERVER_ADDRESS>
```
