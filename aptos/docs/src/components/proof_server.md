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
and leverages the [`lurk-lab/sphinx`](https://github.com/lurk-lab/sphinx) zkVM to generate the proofs and verify them.

In the design document of both the [epoch change proof](../design/epoch_change_proof.md) and
the [inclusion proof](../design/inclusion_proof.md), we describe what each program has to prove. Most computations
performed by the proof programs are directed towards cryptographic operations, such as verifying signatures on the block
header.

To accelerate those operations, we leverage some out-of-VM circuits called **pre-compiles** that are optimized for those
specific operations. The following libraries that make use of our pre-compiles are used in our codebase:

- [bls12_381](https://github.com/lurk-lab/bls12_381/tree/zkvm): A library for BLS12-381 operations based on
  [`zkcrypto/bls12_381`](https://github.com/zkcrypto/bls12_381) making use of pre-compiles for non-native arithmetic. Used
  for verifying the signatures over block header.
- [sha2](https://github.com/sp1-patches/RustCrypto-hashes/tree/patch-v0.10.8): A library for SHA-256 hashing making use of
  pre-compiles for the compression function. Used to hash the message signed by the committee and other pieces of data.
- [tiny-keccak](https://github.com/sp1-patches/tiny-keccak/tree/patch-v2.0.2): A library for SHA-3 hashing, making use of
  pre-compiles for the compression function. Used for hashing the internal Aptos data structures and verifying the
  `SparseMerkleProof`.

The code to be proven is written in Rust and then compiled to RISC-V binaries, stored in `aptos/aptos-programs/artifacts/`.
We then use Sphinx to generate the proofs and verify them based on those binaries. The generated proofs can be STARKs, which
are faster to generate but cannot be verified directly on-chain, or wrapped in a SNARK, which take longer to generate but can
be verified cheaply on-chain.

## Server

The server is a layer added on top of the proving service that makes it available to external users. It is a simple
TCP server that is open to incoming connections on a port specified at runtime.

The server is divided in two, with one main entrypoint. This allows us to handle the worst-case scenario of having to
generate both proofs in parallel, since each server handles one proof at a time. It is possible to generate and verify
both STARK core proofs and SNARK proofs.

The RPC protocol used by the servers is a very simple length-prefixed protocol passing serialized messages back and forth.
The messages are defined in [`proof-server/src/types/proof_server.rs`](https://github.com/lurk-lab/zk-light-clients/blob/dev/aptos/proof-server/src/types/proof_server.rs).
See also the documentation on the [client](./client.md).
