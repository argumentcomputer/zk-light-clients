# Light Client container configuration

To ease the deployment of our proof servers, we provide a set of Docker configuration file that helps to build and run 
them.

## Notice

⚠️ The following commands should be run in the context of the root of the repository.

The current state of the Helm Chart template expects the user to be using AWS EKS
as the Kubernetes provider. The Helm Chart is not yet compatible with other providers.

It also expects the user to label the nodes with the following `r7iz.metal-32xl`
label.

## Dockerfile

The Dockerfile leverages multi-stage builds to create an image that contains the `proof-server` binary.
We use this Dockerfile to create the images for all the proof servers developed
in the repository. The images can be found under [the packages listed for the repository](https://github.com/orgs/argumentcomputer/packages?repo_name=zk-light-clients).

> Note: For more information about the proof server feel free to refer to the 
> documentation  of the specific Light Client.

The `Dockerfile` specifically targets an Linux machine with `avx512_ifma` and `avx512_vbmi2`
support. Make sure that you run the container on such machine.

## Run the Proof Servers images

We have two ways to run the proof server images, either via [`docker compose`](https://docs.docker.com/compose/)
or via a dedicated [Helm chart for Kubernetes](https://helm.sh/).

### Docker Compose

The `docker/compose` directory contains the necessary files to run the proof 
servers using Docker Compose. It is only needed to set the environment variables
and change the image to the desired one to run the project.



#### Setting up the Environment Variables

The project uses environment variables to configure the proof server. These variables are defined in a `.env` file 
located in the
`docker/compose` directory. An example .env file is provided as
`.example.env`. Some environment variables are common to all Light Clients and others are specific to one implementation.

**Variables**

- `PRIMARY_ADDR`: The address of the primary server (e.g., `0.0.0.0`).
- `PRIMARY_PORT`: The port number for the primary server (e.g., `6379`).

> **Note**
> 
> There are also some specific environment variables that are used by the proof servers.
> These variables are meant to optimize the time taken to generate proofs for each 
> Light Client. Make sure that you refer to the `benchmark/configuration.md` file
> of the Light Client you want to deploy a proof server for.

#### Set the desired image

The `docker-compose.yml` file contains the definition of the services that will be run. 
The `image` field in the service definition should be changed to the desired image. The images can be 
found in the [packages](https://github.com/orgs/argumentcomputer/packages?repo_name=zk-light-clients).

```yaml
services:
  server-primary:
    image: ghcr.io/argumentcomputer/<aptos|ethereum|kadena>-proof-server:<tag>
```

#### Running the Docker Compose

You can start the proof server with the following command:

```bash
docker compose -f docker/compose/docker-compose-proof-servers.yml up
```

This command will start the container as defined in the docker-compose.yml file. 
The proof server will start running, and you can interact with 
it as defined in the project documentation.

### Helm Chart

To deploy the proof servers using Kubernetes, we provide a Helm chart in the `proof-server-chart`
directory. The pre-requisite to run the Helm chart is to have a Kubernetes cluster running.
To help get one running we have a dedicated `eksctl` configuration file in the `k8s` directory.
It leverages [`AWS EKS`](https://aws.amazon.com/eks/) to create a cluster that we can leverage to deploy the Helm chart.

To install `eksctl`, follow the instructions from their [official documentation](https://eksctl.io/installation/).
Also, make sure that the user you are using have the sufficient permissions to create an EKS cluster.
They are also described in the [official documentation](https://eksctl.io/usage/minimum-iam-policies/).

#### Create the EKS Cluster

To create the EKS cluster, run the following command:

```bash
eksctl create cluster -f eksctl/cluster-config.yaml
```

This operation will take some time to complete. Once the cluster is created, you can deploy the Helm chart.

#### Deploy the Helm Chart

To deploy the Helm chart, run the following command:

```bash
helm install proof-server ./proof-server-chart/
```

If everything went well you should be able to get the entrypoint to communicate
with your pods:

```bash
$ kubectl get service

NAME                   TYPE           CLUSTER-IP      EXTERNAL-IP                                                               PORT(S)        AGE
proof-server-service   LoadBalancer   10.100.210.63   a55366eb9dd124182a37c7ccfa8a0f53-1123495416.us-east-2.elb.amazonaws.com   80:30262/TCP   31s
```

And the pods running:

```bash
$ kubectl get pods

NAME                                       READY   STATUS        RESTARTS   AGE
proof-server-deployment-8688f88954-cl7vw   1/1     Running       0          59s
proof-server-deployment-8688f88954-wfg6p   1/1     Running       0          43s
```
