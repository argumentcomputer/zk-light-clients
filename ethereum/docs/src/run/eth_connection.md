# Connect to Ethereum

This section will guide you through the process of connecting the Ethereum Light Client to an Ethereum node so that it
can
fetch the necessary data to generate the proofs.

There three main components that the Light Client needs to connect to:

- Checkpoint provider: The Checkpoint Provider is responsible for providing the Light Client with the latest checkpoints
  made available
  for [the sync protocol](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/light-client/sync-protocol.md).
- Beacon node: The Beacon Node is responsible for providing the Light Client with the necessary data to handle the parts
  of the proving related to consensus on the chain.
- Execution RPC endpoint: The Execution RPC endpoint is responsible for providing the Light Client with the necessary
  data to prove value inclusion in the state of the chain.

## Checkpoint Provider

The Checkpoint Provider is responsible for providing the Light Client with the latest checkpoints made available for the
sync protocol. A community maintained list of Checkpoint Providers can be found
on [eth-clients.github.io](https://eth-clients.github.io/checkpoint-sync-endpoints/).

For our Light Client, we recommend to use the [https://sync-mainnet.beaconcha.in](https://sync-mainnet.beaconcha.in)
endpoint.

## Beacon Node

The Beacon Node is responsible for providing the Light Client with the necessary data to handle the parts of the proving
related to consensus on the chain. There are multiple ways to get such an endpoint, such as leveraging one provided by
an
infrastructure company (such as [Ankr](https://www.ankr.com/docs/rpc-service/chains/chains-api/eth-beacon/) ...) or
leverage
a public one, such as the one provided by [a16z](https://www.lightclientdata.org).

In this documentation, we will use the endpoint [https://www.lightclientdata.org](https://www.lightclientdata.org).

> **Note**
>
> If you decide to use an infrastructure provider, make sure that the endpoints we need are properly available. Those
> endpoints can be found
>
in [the `BeaconClient` file](https://github.com/lurk-lab/zk-light-clients/tree/dev/ethereum/light-client/src/client/beacon.rs).

## Execution RPC Endpoint

The Execution RPC endpoint is responsible for providing the Light Client with the necessary data to prove value
inclusion
in the state of the chain. The Light Client needs to connect to an Ethereum node that exposes the necessary RPC
endpoints.

The RPC endpoint to be used to fetch this data is [`eth_getProof`](https://eips.ethereum.org/EIPS/eip-1186). This RPC
endpoint can be access through various RPC provider such
as [Infura](https://docs.infura.io/api/networks/polygon-pos/json-rpc-methods/eth_getproof)
or [Chainstack](https://docs.chainstack.com/reference/getproof).