# Ethereum Nodes

In order to generate the two proofs composing the Light Client, it is needed to
fetch data from the Ethereum network. To retrieve this data, the Light Client
needs to interact with both a node from [the Beacon chain](https://ethereum.org/en/roadmap/beacon-chain/)
and from [the execution chain](https://ethereum.org/en/developers/docs/nodes-and-clients/#execution-clients).

## Beacon Chain Node

The Beacon Node is responsible for providing the Light Client with the necessary data to handle the parts of the proving
related to consensus on the chain. There are multiple ways to get such an endpoint, such as leveraging one provided by
an infrastructure company (such as [Ankr](https://www.ankr.com/docs/rpc-service/chains/chains-api/eth-beacon/) or
leveraging a public one, such as the one provided by [a16z](https://www.lightclientdata.org).

## Execution RPC Endpoint

The Execution RPC endpoint is responsible for providing the Light Client with the necessary data to prove value
inclusion
in the state of the chain. The Light Client needs to connect to an Ethereum node that exposes the necessary RPC
endpoints.

The RPC endpoint to be used to fetch this data is [`eth_getProof`](https://eips.ethereum.org/EIPS/eip-1186). This RPC
endpoint can be accessed through various RPC provider such
as [Infura](https://docs.infura.io/api/networks/polygon-pos/json-rpc-methods/eth_getproof)
or [Chainstack](https://docs.chainstack.com/reference/getproof).