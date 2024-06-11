# Light Client container configuration

To ease the execution and deployment of our Light Client implementation, we provide a set of Docker configuration file
that helps to build and run the necessary components.

> Note: The following indications are meant to run the Light Client
> using [docker compose](https://docs.docker.com/compose/).
> A set of instructions exists for k8s in [its dedicated README](./k8s/README.md).

## Notice

⚠️ The following commands should be run in the context of the `aptos` directory.

## Dockerfile

The Dockerfile leverages multi-stage builds to create an image that contains all three
binaries (`client`, `server_primary`, and `server_secondary`).
The same image is used across the three containers to have all of our proof servers and the client.

> Note: For more information about those binaries and how they interact, please refer
> to [the `proof-server` README](../proof-server/README.md).

### Building the Docker Image

Before building the Docker image, you need to set up a `secret_github_token.txt` file in the root directory of the
project.
This file should contain a valid GitHub token that has read access to the private repositories. This token is used for
authentication when cloning the Sphinx repository during the Docker image build process.

You can build the Docker image using the following command:

```bash
docker build --secret id=github_token,src=secret_github_token.txt -t lurk-lab/aptos-light-client:latest -f ./docker/Dockerfile .
```

### Setting up the Environment Variables

The project uses environment variables to configure the proof servers and the client. These variables are defined in a
.env
file located in the docker directory. An example .env file is provided as `.example.env`. Here's what each variable
does:

- `PRIMARY_ADDR`: The address of the primary server (e.g., `0.0.0.0`).
- `PRIMARY_PORT`: The port number for the primary server (e.g., `6379`).
- `SECONDARY_ADDR`: The address of the secondary server (e.g., `0.0.0.0`).
- `SECONDARY_PORT`: The port number for the secondary server (e.g., `6380`).
- `APTOS_NODE_URL`: The URL of the Aptos node (e.g., `127.0.0.1:8080`).

### Running the Docker Compose

Once the Docker image is built and the environment variables are set, you can start the proof servers and the client
using Docker Compose with the following command:

```bash
docker compose -f docker/docker-compose.yml up
```

This command will start the containers as defined in the docker-compose.yml file. The proof servers and the client will
start running, and you can interact with them as defined in the project documentation.
