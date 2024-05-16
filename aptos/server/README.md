# Aptos Light Client Server

An RPC server for the Aptos Light Client, enabling remote execution of the proof-generating algorithms defined in the `aptos-lc` crate.

To run the server, call

```bash
$ cargo run --release -- <PORT>
```

Where `<PORT>` is the port the server should listen to.

## Endpoints

The server provides two endpoints:

* `prove_ratcheting` generates proofs about correct epoch transitions
* `prove_merkle_inclusion` generates proofs about merkle inclusions of transactions
* `verify_ratcheting_proof` verifies a ratcheting proof
* `verify_merkle_inclusion_proof` verifies a merkle inclusion proof

Since the server is built with [`tonic_rpc`](https://docs.rs/tonic-rpc/latest/tonic_rpc/), an implementation for a client that can connect to a server and access its API is generated automatically.

```rust
let mut client = aptos_client::AptosClient::connect(addr).await?;

let ratcheting_proof: SP1Proof =
    client.prove_ratcheting(ratcheting_proof_request).await?.into_inner();
let merkle_inclusion_proof: SP1Proof =
    client.prove_merkle_inclusion(merkle_inclusion_proof_request).await?.into_inner();

let ratcheting_proof_verified: bool =
    client.verify_ratcheting_proof(ratcheting_proof).await?.into_inner();
let merkle_inclusion_proof_verified: bool =
    client.verify_merkle_inclusion_proof(merkle_inclusion_proof).await?.into_inner();

assert!(ratcheting_proof_verified);
assert!(merkle_inclusion_proof_verified);
```

Where:
* `addr` is the address of the server
* `ratcheting_proof_request: server::RatchetingProofRequest` contains the data for generating the ratcheting proof
* `merkle_inclusion_proof_request: server::MerkleInclusionProofRequest` contains the data for generating the merkle inclusion proof
