# Kubernetes Configuration for Light Client

This project consists of three main components: `client`, `server-primary`, and `server-secondary`. Each of these components has a corresponding Kubernetes deployment and service configuration file. The Docker images used in these deployments are built using the Dockerfile located in the parent directory.

## Prerequisites

Before you begin, ensure that you have installed Docker and Minikube. You can find the installation instructions at the following links:

- Docker: [https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)
- Minikube: [https://minikube.sigs.k8s.io/docs/start/?arch=%2Flinux%2Fx86-64%2Fstable%2Fbinary+download](https://minikube.sigs.k8s.io/docs/start/?arch=%2Flinux%2Fx86-64%2Fstable%2Fbinary+download)

## Running the Project

Navigate to the `<repository-folder>/aptos` directory and follow these steps:

1. Start Minikube with Docker as the driver:

```bash
minikube start --driver=docker
```

2. Set the Docker context to Minikube:

```bash
eval $(minikube -p minikube docker-env)
```

3. Create a `secret_github_token.txt` file in the root directory of the project. This file should contain a valid GitHub 
token that has read access to the private repositories. This token is used for authentication when cloning the Sphinx 
repository during the Docker image build process.

4. Build the Docker image using the following command:

```bash
docker build --secret id=github_token,src=secret_github_token.txt -t lurk-lab/aptos-light-client:latest -f ./docker/Dockerfile .
```

5. Apply the Kubernetes configuration files:

```bash
minikube kubectl -- apply -f ./docker/k8s/
```

After running these commands, the `client`, `server-primary`, and `server-secondary` should be up and running in your 
Minikube environment.