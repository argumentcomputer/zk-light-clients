# Light Client container configuration

To ease the execution and deployment of our Light Client implementation, we provide a set of Docker configuration file that helps to build and run the necessary components.

> Note: The following indications are meant to run the Light Client
> using [docker compose](https://docs.docker.com/compose/).
> A set of instructions exists for k8s in [its dedicated README](k8s/README.md).

## Notice

⚠️ The following commands should be run in the context of the root of the repository.

## Dockerfile

The Dockerfile leverages multi-stage builds to create an image that contains all three binaries (`client`,
`server_primary`, and
`server_secondary`). The same image is used across the three containers to have all of our proof servers and the client.

> Note: For more information about those binaries and how they interact, please refer
> to [the `proof-server` README](../aptos/proof-server/README.md).

### Setting up the Environment Variables

The project uses environment variables to configure the proof servers and the client. These variables are defined in a .env file located in the
`docker/compose` directory. An example .env file is provided as
`.example.env`. Some environment variables are common to all Light Clients and others are specific to one implementation.

**Common variables**

- `PRIMARY_ADDR`: The address of the primary server (e.g., `0.0.0.0`).
- `PRIMARY_PORT`: The port number for the primary server (e.g., `6379`).
- `SECONDARY_ADDR`: The address of the secondary server (e.g., `0.0.0.0`).
- `SECONDARY_PORT`: The port number for the secondary server (e.g., `6380`).

**Aptos variables**

- `APTOS_NODE_URL`: The URL of the Aptos node (e.g., `127.0.0.1:8080`).

**Ethereum variables**

- `CHECKPOINT_PROVIDER_ADDRESS`: The address of the checkpoint provider for the Ethereum client. (e.g.,
  `https://sync-mainnet.beaconcha.in`)
- `BEACON_NODE_ADDRESS`: The address of the Beacon node used to query consensus data  (e.g.,
  `https://www.lightclientdata.org`)
-

`RPC_PROVIDER_ADDRESS`: The address that the client will use to fetch execution data through RPC. Can be access through various RPC provider such as [Infura](https://docs.infura.io/api/networks/polygon-pos/json-rpc-methods/eth_getproof)
or [Chainstack](https://docs.chainstack.com/reference/getproof).

### Running the Docker Compose

Once the Docker image is built and the environment variables are set, you can start the proof servers and the client using Docker Compose with the following command:

```bash
docker compose -f docker/compose/docker-compose-proof-servers.yml -f docker/compose/docker-compose-<aptos|ethereum>.yml build --build-arg LIGHT_CLIENT=<aptos|ethereum> && \
  docker compose -f docker/compose/docker-compose-proof-servers.yml -f docker/compose/docker-compose-<aptos|ethereum>.yml up
```

This command will start the containers as defined in the docker-compose.yml file. The proof servers and the client will start running, and you can interact with them as defined in the project documentation.
