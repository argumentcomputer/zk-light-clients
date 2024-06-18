# Proof Server

The Proof Server is a component of the Light Client that is responsible for generating and serving proofs to the client.
The server is designed to be stateless and can be scaled horizontally to handle a large number of requests. The Proof
Server can be divided in two distinct implementations:

- Proof programs: The proof program contains the logic that will be executed by our Proof server, generating
  the succinct proof to be verified.
- Server: The server is a layer added on top of the proving service that makes it available to external users.

## Proof programs

This layer of the Proof Server corresponds to the code for which the execution has to be proven. Its logic is the core
of our whole implementation and ensures the validity of what we are trying to achieve. The programs are written in Rust
and leverages our zkVM [`lurk-lab/sphinx`](https://github.com/lurk-lab/sphinx) to generate the proofs and verify them.

In the design document of both the [epoch change proof](../design/epoch_change_proof.md) and
the [inclusion proof](../design/inclusion_proof.md), we went over what each program has to prove. Most computations
(happening while generating a proof) are directed towards cryptographic operations, such as handling signatures on the block
header.

To accelerate those operations, we leverage some out-of-VM circuits called **pre-compiles** that are optimized for those
specific operations. The following pre-compiles are used in our codebase:

- [BLS12-381](https://github.com/lurk-lab/bls12_381/tree/zkvm): A pre-compile that handles BLS12-381 operations,
  used for handling the signatures over our block headers.
- [sha2](https://github.com/sp1-patches/RustCrypto-hashes/tree/patch-v0.10.8): A pre-compile that handles the SHA-256
  hashing algorithm, used to hash the message signed by the committee.
- [tiny-keccak](https://github.com/sp1-patches/tiny-keccak/tree/patch-v2.0.2): A pre-compile that handles the
  Keccak256 hashing algorithm, used for hashing the internal Aptos data structure.

The code to be proven is written in Rust and then compiled to RISC-V binaries. We then use the Sphinx tool to generate
the proofs and verify them based on those binaries.

## Server

The server is a layer added on top of the proving service that makes it available to external users. It is a simple
HTTP server that is open to incoming TCP stream connection on the port that has been specified at runtime.

The server is divided in two, with one main entrypoint. This allows us to handle the worst-case scenario of having to
generate both proofs in parallel. It is possible to handle both STARK core proofs and SNARK proofs.