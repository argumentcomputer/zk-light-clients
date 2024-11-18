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

In the design document of both the [Sync Committee change proof](../design/committee_change_proof.md) and
the [inclusion proof](../design/inclusion_proof.md), we describe what each program has to prove. Most computations
performed by the proof programs are directed towards cryptographic operations, such as verifying signatures on the block
header.

To accelerate those operations, we leverage some out-of-VM circuits called **pre-compiles** that are optimized for those
specific operations. The following libraries that make use of our pre-compiles are used in our codebase:

- [bls12_381](https://github.com/argumentcomputer/bls12_381/tree/zkvm): A library for BLS12-381 operations based on
  [`zkcrypto/bls12_381`](https://github.com/zkcrypto/bls12_381) making use of pre-compiles for non-native arithmetic. Used
  for verifying the signatures over block header.
- [sha2](https://github.com/sp1-patches/RustCrypto-hashes/tree/patch-v0.10.8): A library for SHA-256 hashing making use of
  pre-compiles for the compression function. Used to reconstruct the Merkle Root from a Merkle Proof.
- [tiny-keccak](https://github.com/sp1-patches/tiny-keccak/tree/patch-v2.0.2): A library for SHA-3 hashing, making use of
  pre-compiles for the compression function. Used for hashing the sync committee data.

The code to be proven is written in Rust and then compiled to RISC-V binaries, stored in `ethereum/ethereum-programs/artifacts/`.
We then use Sphinx to generate the proofs and verify them based on those binaries. The generated proofs can be STARKs, which
are faster to generate but cannot be verified directly on-chain, or wrapped in a SNARK, which take longer to generate but can
be verified cheaply on-chain.

## Server

The server is a layer added on top of the proving service that makes it available to external users. It is a simple
HTTP server that is open to incoming connections on a port specified at runtime.

The prover can be ran with two specific mode, either `single` or `split`. 

`single`  means that only one instance of the prover will be handling all the proof generation.
As the resource consumption for proof generation is quite high, it means that 
only one types of proof will be generated at any given time. In the context of the 
Ethereum light client, it means that once every 54.6 hours the client will have to wait
for the proof of the Sync Committee change to be finalized before resuming the production
of the inclusion proofs.

`split` means that two instances of the prover will be running, one for each proof type.
In such a scenario, the latency created by the `single` mode is avoided, but the resource
to be allocated to the prover have to be doubled. The interaction between each proof server
is done through HTTP as a client does with a prover.

> **Info**
> 
> In our [Kubernetes configuration](https://github.com/argumentcomputer/zk-light-clients/tree/dev/docker)
> the proof server is ran using `single` mode and the load balancing is handled by
> K8S itself.

The HTTP endpoints available for the proof server can be found in the section about [the operation of
the bridge](../run/operate_bridge.md). The messages sent over HTTP are defined
in [`proof-server/src/types/proof_server.rs`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/ethereum/light-client/src/types/network.rs).