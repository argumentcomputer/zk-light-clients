# Aptos Light Client Server

An RPC server for the Aptos Light Client, enabling remote execution of the proof-generating algorithms defined in the `aptos-lc` crate.

To run the server, call

```bash
$ cargo run --release -- <PORT>
```

Where `<PORT>` is the port the server should listen to.

## Endpoints

The server provides two endpoints:

* `ratchet` generates proofs about correct epoch transitions
* `merkle` generates proofs about merkle inclusions of transactions

Since the server is built with [`tonic_rpc`](https://docs.rs/tonic-rpc/latest/tonic_rpc/), an implementation for a client that can connect to a server and access its API is generated automatically.

```rust
let mut client = aptos_client::AptosClient::connect(addr).await?;
let ratchet_proof: SP1DefaultProof = client.ratchet(ratchet_request).await?.into_inner();
let merkle_proof: SP1DefaultProof = client.merkle(merkle_request).await?.into_inner();
```

Where:
* `addr` is the address of the server
* `ratchet_request: server::RatchetRequest` contains the data for generating the ratcheting proof
* `merkle_request: server::MerkleRequest` contains the data for generating the merkle inclusion proof
