# Aptos Light Client Proof Server

This server supports parallel generation of inclusion and epoch change proofs for the Aptos Light Client as well as
verification for those proofs.

Internally, it's (currently) implemented as two servers that work in tandem.

* The *primary server* is capable of handling requests related to inclusion proofs internally;
* Requests related to epoch change proofs are handled by the *secondary server*

However, a client just needs to interact with the primary server directly.

## Run an Aptos node

You need to run an Aptos node to fetch chain data. The current version
of the node the has to be ran is a fork found
here: [`lurk-lab/aptos-core:release/aptos-node-v1.14.0-patched`](https://github.com/lurk-lab/aptos-core/tree/release/aptos-node-v1.14.0-patched)
and its current head at
commit [`d94b897`](https://github.com/lurk-lab/aptos-core/tree/d94b8974451d088e42882f9e1f761dfddfada345).

To run the node, you first need to clone the repository:

```shell
$ git clone -b feature/new-endpoints git@github.com:tchataigner/aptos-core.git
```

Then, you will need to download some configuration files:

```shell
$ cd aptos-core
$ curl -O https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/mainnet/waypoint.txt
$ curl -O https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/mainnet/genesis.blob
```

For the last piece of configuration; you will need to set a `fullnode.yaml` file in the root of the repository.
Here is an example of a setup:

```yaml
base:
  # Update this value to the location you want the node to store its database
  data_dir: "/home/thomas/aptos/db"
  role: "full_node"
  waypoint:
    # Update this value to that which the blockchain publicly provides. Please regard the directions
    # below on how to safely manage your genesis_file_location with respect to the waypoint.
    from_file: "./waypoint.txt"

execution:
  # Update this to the location to where the genesis.blob is stored, prefer fullpaths
  # Note, this must be paired with a waypoint. If you update your waypoint without a
  # corresponding genesis, the file location should be an empty path.
  genesis_file_location: "./genesis.blob"

full_node_networks:
  - discovery_method: "onchain"
    # The network must have a listen address to specify protocols. This runs it locally to
    # prevent remote, incoming connections.
    listen_address: "/ip4/127.0.0.1/tcp/6180"
    network_id: "public"

# API related configuration, making it available at a given address.
api:
  enabled: true
  # Update this to fit your deployment address for the node.
  address: 127.0.0.1:8080

# /!\ IMPORTANT/!\
# This configuration is especially important for the proof server to work.
# This configuration allows us to access the state at each new block,
# effectively allowing us to create inclusion proof about accounts.
storage:
  buffered_state_target_items: 1

# This configuration allows for a fast synchronisation of the node.
state_sync:
  state_sync_driver:
    bootstrapping_mode: DownloadLatestStates
    continuous_syncing_mode: ExecuteTransactionsOrApplyOutputs

```

Finally, you can run the node:

```shell
$ cargo run -p aptos-node --release -- -f ./fullnode.yaml
```

## Running the Proof Server

Start the secondary server:

```shell
$ cargo run --release --bin server_secondary -- -a 127.0.0.1:6380
```

Start the primary server:

```shell
$ cargo run --release --bin server_primary -- -a 127.0.0.1:6379 --snd-addr 127.0.0.1:6380
```

The primary server needs to know the address of the secondary address. It's provided in the `snd-addr` argument.

### A dummy client

`client.rs` provides an implementation for a client that can make requests to the proof server.

Once both servers and the Aptos node are running, you can make the following calls in separate terminals at the same
time:

```shell
$ cargo run -p proof-server --release --bin client -- --proof-server-address 100.121.74.49:6379 --aptos-node-url 100.106.99.21:8080
```

> Note: use the environment variable `RUST_LOG="debug"` to get more insight on the client execution.

The server should be able to handle both calls above in parallel.

### Further details

For more details on how to interact with the primary server, please call the primary server using the `--help` argument.
It contains information about the protocol a client needs to follow.

Also, one of the main purposes of the dummy client is to showcase how a client can interact with the server.
So it can be a helpful source to get started on a real client.

## Running the benchmark

We have implemented a benchmark for the proof server. It can be run with the following command:

```shell
$ RUST_LOG=debug RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable" PRIMARY_ADDR="127.0.0.1:8080" SECONDARY_ADDR="127.0.0.1:8081" cargo +nightly bench --bench proof_server
```

This benchmark will spawn the two servers locally and make two requests in parallel to them. This generates both proofs
at the same time in the same machine. It measures to main metrics for each proof:

- `e2e_proving_time`: Time taken to send a request to the proof server, generate the proof and receive the response.
- `request_response_proof_size`: Size of the proof returned by the server.

The output is formatted as such:

```json
{
  "inclusion_proof": {
    "e2e_proving_time": 107678,
    "request_response_proof_size": 20823443
  },
  "epoch_change_proof": {
    "e2e_proving_time": 125169,
    "request_response_proof_size": 23088485
  }
}
```

> Note: As the proof server is run with the `RUST_LOG=debug` environment variable, it is also possible to grab the inner
> metrics
> from Sphinx.