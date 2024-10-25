## Aptos Light Client

This is a light client for the Aptos blockchain. It is written in Rust and lives in the workspace defined in this directory. In this README we will go over a few details that need to be known before hopping into development.

For a more detailed overview of the Light Client and its components, and how to run and benchmark it, you can refer to the mdBook at https://argumentcomputer.github.io/zk-light-clients/aptos

It can also be run locally with:

```bash
cd docs && \
  mdbook serve --open
```

Then navigate to [`localhost:3000`](http://localhost:3000).

## Layout

The workspace is divided into the following:

-
`proof-server`: The server layer on top of the proving library. It exposes a REST API to generate proofs for the light client.
-
`light-client`: The main library that contains the light client implementation. It is in charge of producing proofs regarding the consensus of the chain and inclusion of some account values in a Merkle Tree.
- `core`: The core library that contains the data structures and utilities used by the light client.
- `aptos-programs`: A library that exposes the Sphinx programs used to generate proofs for our light client.*
- `programs/*`: Actual implementations of the Sphinx programs.

## Development

When developing, you might have to update the programs' implementation. The programs implementations are located in
`./programs/*` and the compiled binaries are located in
`./aptos-programs/artifacts`. Currently, artifacts binaries are generated in two ways:

- Automated: There is a build script located at
  `./aptos-programs/build.rs` that will compile all the programs and place them in the `./aptos-programs/artifacts`
  folder. To enable this feature, it is needed to set the environment variable `LC_PROGRAM_AUTOBUILD=1`.
- Manual: You can also compile the programs manually using `make` by running the following command in the
  `./aptos-programs` folder:
  ```shell
    make
    ```

## Running the Project

To run all the Light Client components, you can either run them manually (refer to [the README in the `proof-server`
crate](./proof-server/README.md))
or leverage our docker files (see [the README in the `docker` folder](../docker/README.md)).

## Benchmarks

For more information about how to run the benchmarks, please refer to the dedicated section of the mdBook. Otherwise, the READMEs can be found in the [
`docs/src/benchmark`](./docs/src/benchmark/overview.md) folder.
