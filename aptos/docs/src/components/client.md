# Client

The client is the coordinator of the Light Client. It is responsible for orchestrating the communication between the
Proof Server and the Aptos Full Node. In our current example implementation it can also serve as a drop-in replacement
for what an on-chain verifier would be responsible for.

The client also demonstrates how to request data from our Aptos PFN endpoints, how to forward it to the proof servers
using the simple binary RPC protocol, example and how to parse the received responses from the server. See
[the source](https://github.com/argumentcomputer/zk-light-clients/blob/dev/aptos/proof-server/src/bin/client.rs)
for more details.

The client has two phases:

- **Initialization**: The client fetches the initial data from the Aptos node and generates the initial state for
  itself and the verifier.
- **Main Loop**: The client listens for new data from the Aptos node and generates proofs for the verifier to verify.
  This includes new proofs for epoch changes.

The current implementation of the client is specifically designed to cover the worst case scenario of having to handle
the proofs generation in parallel. This flow happens during initialization where we prove the latest epoch change on the
Aptos network while producing an inclusion proof for a given account at the latest block.

The bundled example client currently only requests and verifies STARK proofs. The proof servers have support for generating
and verifying SNARK proofs, but the example client does not yet make use of this.