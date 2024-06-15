# Client

The client is the coordinator of the Light Client. It is responsible for orchestrating the communication between the
Proof Server and the Aptos Full Node. In our current implementation it also serves as a drop-in replacement for what
would be a verifier deployed on a destination chain.

The client lifecycle can be divided in two phases:

- **Initialization**: In this phase, the client fetches the initial data from the Aptos node and
  generates the initial state for itself and the verifier.
- **Main Loop**: In this phase, the client listens for new data from the Aptos node and generates
  proofs for the verifier to verify.

The current implementation of the client is specifically designed to cover the worst case scenario of having to handle
the proofs generation in parallel. This flow happens during initialization where we prove the latest epoch change on the
Aptos network while producing an inclusion proof for a given account at the latest block.