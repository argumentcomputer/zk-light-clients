# Run the Client

To coordinate the communication to all the components, we need to run the Client. The Client will communicate each
component to fetch the data and generate the proofs.

## Requirements

Make sure to finish the [initial configuration](./configuration.md) first.

## Launch the Client

With our deployment machine properly configured, we can run the client.

The client can either work with STARK or SNARK proofs. To configure this, the
environment variable `MODE` can be set to either `STARK` or `SNARK`. The default is `STARK`.

```bash
git clone git@github.com:argumentcomputer/zk-light-clients.git && \
  cd zk-light-clients/kadena && \
  MODE=SNARK RUST_LOG="debug" cargo run -p light-client --release --bin client -- -c <KADENA_NODE_URL> -p <PROOF_SERVER_ADDRESS>
```

> **Info**
> 
> An example of a public Kadena node URL  for mainnet is `http://api.chainweb.com`.

The client only needs to communicate with the primary proof server, since requests to the secondary server are automatically forwarded.

With this, the Client should run through its initialization process and then start making requests to both the Proof Server and
the Kadena node, generating proofs as needed in a loop.
