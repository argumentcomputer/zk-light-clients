# Run the Client

The final component that we need to set up is the Client. As both the Aptos Full Node and the Proof Server are
available, we just need to point the client to the necessary addresses so it can communicate with both.

## Requirements

Make sure to finish the [initial configuration](./configuration.md) first.

## Launch the Client

With our deployment machine properly configured, we can run the client.

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/aptos/proof-server && \
  RUST_LOG="debug" cargo +nightly-2024-05-31 run -p proof-server --release --bin client -- --proof-server-address <PRIMARY_SERVER_ADDRESS> --aptos-node-url <APTOS_NODE_URL>
```

The client only needs to communicate with the primary proof server, since requests to the secondary server are automatically forwarded.

With this, the Client should run through its initialization process and then start making requests to both the Proof Server and
the Aptos Full Node, generating proofs as needed in a loop.
