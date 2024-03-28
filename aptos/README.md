## Aptos Light Client

This is a light client for the Aptos blockchain. It is written in Rust and lives in the workspace defined in this
directory.
In this README we will go over a few specifities that need to be known before hoping in development.

## Layout

The workspace is divided into the following:

- `light-client`: The main library that contains the light client implementation. It is in charge of producing proofs
  regarding the consensus of the chain and inclusion of some account values in a Merkle Tree.
- `core`: The core library that contains the data structures and utilities used by the light client.
- `aptos-programs`: A library that exposes the WP1 programs used to generate proofs for our light client.*
- `programs/*`: Actual implementations of the WP1 programs.

## Development

When developing, you might have to update the programs implementation. The current implementation of the workspace does
not allow for automatic generation of the assets once an update was done. Instead, you will have to manually execute
the Makefile in the `aptos-programs` directory to generate the assets. This should be automated in the future.