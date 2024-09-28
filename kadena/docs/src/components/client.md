# Client

The client is the coordinator of the Light Client. It is responsible for orchestrating the communication between the
Proof Server and the Ethereum nodes. In our current example implementation it can also serve as a drop-in replacement
for what an on-chain verifier would be responsible for.

The client also demonstrates how to request data from the Ethereum nodes endpoints, how to forward it to the proof servers
using the simple binary RPC protocol, example and how to parse the received responses from the server. See
[the source](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/bin/client.rs)
for more details.

The client has two phases:

- **Initialization**: The client fetches the initial data from the Kadena node to set
an initial state for itself and the verifier.
- **Main Loop**: The client listens for new data from the Kadena node and generates proofs for the verifier to verify.
  This includes new proofs for the longest chain and SPV.
