## Ethereum Light Client

This is a light client for the Ethereum blockchain. It is written in Rust and lives in the workspace defined in this
directory.
In this README we will go over a few details that need to be known before hopping into development.

For a more detailed overview of the Light Client and its components, and how to run and benchmark it, you can refer to
the
mdBook. To read it run:

```bash
cd docs && \
  mdbook serve --open
```

Then navigate to [`localhost:3000`](http://localhost:3000).

## Layout

The workspace is divided into the following:

- `light-client`: The main library that contains the light client implementation. It has two main roles:
    - proof server: Produces proofs regarding the sync committee changes and inclusion of some account in the state
      Merkle Tree.
    - client: Coordinate data communication between the Ethereum chain and the proof server to generate the right proofs
      at the right time.
- `core`: The core library that contains the data structures and utilities used by the light client.
- `ethereum-programs`: A library that exposes the Sphinx programs used to generate proofs for our light client.
- `programs/*`: Actual implementations of the Sphinx programs.

## Development

When developing, you might have to update the programs' implementation. The
programs implementations are located in `./programs/*` and the compiled binaries
are located in `./ethereum-programs/artifacts`. Currently, artifacts binaries are
generated in two ways:

- Automated: There is a build script located at `./ethereum-programs/build.rs` that
  will compile all the programs and place them in the `./ethereum-programs/artifacts`
  folder. To enable this feature, it is needed to set the environment variable `LC_PROGRAM_AUTOBUILD=1`.
- Manual: You can also compile the programs manually using `make` by running the following
  command in the `./ethereum-programs` folder:
  ```shell
    make
    ```