# Proof Server

The Proof Server is a component of the Light Client that is responsible for generating and serving proofs to the client.
The server is designed to be stateless and can be scaled horizontally to handle a large number of requests. The Proof
Server can be divided in two distinct implementations:

- **Proof programs**: The proof program contains the logic that will be executed by our Proof server, generating
  the succinct proof to be verified. The proof programs are run inside the Sphinx zkVM and prover.
- **Server**: The server is a layer added on top of the proving service that makes it available to external users via a
  simple protocol.

## Proof programs

This layer of the Proof Server corresponds to the code for which the execution has to be proven. Its logic is the core
of our whole implementation and ensures the correctness of what we are trying to achieve. The programs are written in Rust
and leverages the [`argumentcomputer/sphinx`](https://github.com/argumentcomputer/sphinx) zkVM to generate the proofs and verify them.

In the design document of both the [Longest chain proof](../design/longest_chain.md) and
the [SPV proof](../design/spv.md), we describe what each program has to prove. Most computations
performed by the proof programs are directed towards cryptographic operations, such as hashing
values.

To accelerate those operations, we leverage some out-of-VM circuits called **pre-compiles** that are optimized for those
specific operations. The following pre-compiles are used in our codebase:

- [blake2s](https://github.com/argumentcomputer/RustCrypto-hashes/tree/zkvm/blake2): A library for Blake2s hashing making use of
  pre-compiles for the compression function. Used while calculating the PoW hash for the chain block headers.
- [sha2](https://github.com/argumentcomputer/RustCrypto-hashes/tree/zkvm/sha2): A library for SHA-512 hashing making use of
  pre-compiles for the compression function. Used to calculate the block header hashes.

The code to be proven is written in Rust and then compiled to RISC-V binaries, stored in `kadena/kadena-programs/artifacts/`.
We then use Sphinx to generate the proofs and verify them based on those binaries. The generated proofs can be STARKs, which
are faster to generate but cannot be verified directly on-chain, or wrapped in a SNARK, which take longer to generate but can
be verified cheaply on-chain.

## Server

The server is a layer added on top of the proving service that makes it available to external users. It is a simple
REST server that is open to incoming connections on a port specified at runtime.

The server have two possible mode of operation:
- _Single_: The deployed server will handle all incoming proving and verifying requests.
- _Split_: The deployed server will handle only part of the requests, and will forward the rest to another server.

It is possible to generate and verify both STARK core proofs and SNARK proofs.

The RPC protocol used by the servers is a very simple bytes protocol passing serialized messages back and forth.
The messages are defined in [`light-client/src/types/network.rs`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/types/network.rs).
See also the documentation on the [client](./client.md).