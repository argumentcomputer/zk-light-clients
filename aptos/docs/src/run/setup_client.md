# Run the Client

The final component that we need to set up is the Client. As both the Aptos Full Node and the Proof Server are
available,
one can start the coordination of the proving process between the two of them.

The first setup steps are similar to the Proof Server as they are binaries of the same crate.

## Requirements

Make sure that the configuration specified in [the dedicated section](./configuration.md) are met.

## Launch the Client

With our deployment machine properly configured, we can run the client.

```bash
git clone git@github.com:lurk-lab/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  RUST_LOG="debug" cargo +nightly run -p proof-server --release --bin client -- --proof-server-address <PRIMARY_SERVER_ADDRESS> --aptos-node-url <APTOS_NODE_URL>
```

With this, the Client should start its initialization process and be able to make requests to both the Proof Server and
the Aptos Full Node.