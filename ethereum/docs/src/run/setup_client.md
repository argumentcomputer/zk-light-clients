# Run the Client

To coordinate the communication to all the components, we need to run the Client. The Client will communicate each
component to fetch the data and generate the proofs.

## Launch the Client

With our deployment machine properly configured, we can run the client.

```bash
git clone git@github.com:lurk-lab/zk-light-clients.git && \
  cd zk-light-clients/ethereum && \
  RUST_LOG="debug" cargo +nightly-2024-05-31 run -p light-client --release --bin client -- -c <CHECKPOINT_PROVIDER_ADDRESS> -b <BEACON_NODE_ADDRESS> -p <PROOF_SERVER_ADDRESS>
```