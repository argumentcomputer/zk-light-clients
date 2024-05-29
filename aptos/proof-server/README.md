# Aptos Light Client Proof Server

This server supports parallel generation of inclusion and epoch change proofs for the Aptos Light Client as well as verification for those proofs.

Internally, it's (currently) implemented as two servers that work in tandem.
* The *primary server* is capable of handling requests related to inclusion proofs internally;
* Requests related to epoch change proofs are handled by the *secondary server*

However, a client just needs to interact with the primary server directly.

## Usage instructions

The following instructions assume that both primary and secondary servers are running locally, on ports 6379 and 6380 respectively.

Start the secondary server:

```
cargo run --release --bin server_secondary -- -a 127.0.0.1:6380
```

Start the primary server:

```
cargo run --release --bin server_primary -- -a 127.0.0.1:6379 --snd-addr 127.0.0.1:6380
```

The primary server needs to know the address of the secondary address. It's provided in the `snd-addr` argument.

### A dummy client

`dummy_client.rs` provides an implementation for a client that can make requests to the proof server.

Once both servers are running, you can make the following calls in separate terminals at the same time:

```
cargo run --release --bin dummy_client -- -a 127.0.0.1:6379 inclusion
```

```
cargo run --release --bin dummy_client -- -a 127.0.0.1:6379 epoch-change
```

The server should be able to handle both calls above in parallel.

### Further details

For more details on how to interact with the primary server, please call the primary server using the `--help` argument.
It contains information about the protocol a client needs to follow.

Also, one of the main purposes of the dummy client is to showcase how a client can interact with the server.
So it can be a helpful source to get started on a real client.
