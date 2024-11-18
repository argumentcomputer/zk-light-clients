# Operate the bridge

In the previous sections we have gone over the steps to setup each components that are
available in the source of the repository so that they can start interacting with each
other.

However, in a practical scenario, the client and verifier contracts will have
to be adapted to the use case that a user wants to implement. We will go over the
steps to adapt the components for any use case in this section.

## Adapt the client

### Initialize the client

Before we can start fetching data from the Kadena network, we need to initialize
the client. To do so we need to select a block that we trust being at the tip of the longest chain.
The logic to initialize the client is quite straight forward and an example implementation
can be found [in our mock client](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/bin/client.rs#L263-L311).

### Fetch Kadena data

The first piece that will need some refactoring to adapt to a new use case is the client.
The client should be considered as the main entry point for a bridge, and is responsible
for fetching data from the Kadena network and submitting it to the prover.

The first key data needed for us to fetch are the necessary block headers to prove
that we are dealing with a block that can be considered the longest tip of the chain.
Basically the block we want to make this proof for has to be produced on top of an already
known block and have enough block power mined on top of it. The logic for
fetching the necessary headers in our codebase can be found in [the `get_layer_block_headers` function.](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/client/chainweb.rs#L71-L221).
This function leverages the `/mainnet01/chain/{chain}/header` from Kadena to
fetch the necessary headers from each chain. All the headers are then organized in a 
`Vec<ChainwebLayerHeader>`  where [`ChainwebLayerHeader`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/core/src/types/header/layer.rs#L19-L26) is a struct representing
all the block headers for all chains at a given height. 

The second important piece of data for our proofs are the data necessary to prove
an SPV. Such data can be easily retrieved from the `/mainnet01/chain/{chain}/pact/spv`
endpoint available from a Kadena node API. The `chain` parameter along with
the `requestKey` representing a transaction hash allow us to fetch an SPV for said
transaction. This particular API endpoint will return a [`SpvResponse`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/types/chainweb.rs#L39-L48) struct
that has to be transformed to an [`Spv`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/types/chainweb.rs#L39-L48)
struct to be passed to the prover. An example of this transformation can be found [in the codebase](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/types/chainweb.rs#L55-L64).

## Run the prover

The prover is quite straight forward to run. When ran in `single` mode, the only
parameter to properly set is the address it should listen to for incoming request.

It consists of a lightweight router that will listen to the following routes:
-  (**GET**) `/health`: Operationnal endpoint the returns a 200 HTTP code when the server is ready to receive requests
- (**GET**) `/ready`: Operationnal endpoint the returns a 200 HTTP code when the server is not currently handling a
  request
- (**POST**) `/spv/proof`: Endpoint to submit a proof request for an spv proof
- (**POST**) `/spv/verify`: Endpoint to submit a proof request for an spv proof verification
- (**POST**) `/longest-chain/proof`: Endpoint to submit a proof request for a longest chain proof
- (**POST**) `/longest-chain/verify`: Endpoint to submit a proof request for a longest chain proof verification

For proofs related endpoint the payload is a binary serialized payload that is sent over
HTTP. The Rust type in our codebase representing such types is [`Request`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/types/network.rs#L9-L21).

The bytes payload format is the following:

**Proof generation**

| Name         | Byte offset | Description                                                                                                                                                                                                                                                                                                                                                        |
|--------------|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Request type | 0           | Type of the request payload                                                                                                                                                                                                                                                                                                                                        |
| Proving mode | 1           | Type of the proof that the proof server should generate. `0` for STARK and `1` for SNARK                                                                                                                                                                                                                                                                           |
| Proof inputs | 2           | Serialized inputs for the proof generation. Serialized [`LongestChainIn`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/proofs/longest_chain.rs#L79-L92) for longest chain and serialized [`SpvIn`](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/light-client/src/proofs/spv.rs#L90-L112) for spv. |

**Proof verification**

| Name        | Byte offset | Description                                                                                                                                                                              |
|-------------|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Request type | 0           | Type of the request payload                                                                                                                                                              |
| Proof type  | 1           | Type of the proof that the payload contains. `0` for STARK and `1` for SNARK                                                                                                             |
| Proof | 2           | Bytes representing a JSON serialized [`SphinxProofWithPublicValues`](https://github.com/argumentcomputer/sphinx/blob/36f3f9072dc187612640e2725a2f7524cf2f2215/sdk/src/proof.rs#L21-L28). |

The response bodies are more straight forward:

**Proof generation**

| Name | Byte offset | Description |
|------|-------------|-------------|
| Proof type  | 0           | Type of the proof that the payload contains. `0` for STARK and `1` for SNARK                                                                                                             |
| Proof | 1           | Bytes representing a JSON serialized [`SphinxProofWithPublicValues`](https://github.com/argumentcomputer/sphinx/blob/36f3f9072dc187612640e2725a2f7524cf2f2215/sdk/src/proof.rs#L21-L28). |

**Proof verification**

| Name                          | Byte offset | Description                                                                                |
|-------------------------------|-------------|--------------------------------------------------------------------------------------------|
| Successful proof verification | 0           | A `0` (fail) or `1` (success) byte value representing the success of a proof verification. |

## Adapt the verifier

In the following section we will touch upon how a verifier contract has to be updated
depending on a use case. However, it has to be kept in mind that some core
data will have to be passed even thought some modifications have to be done
for different use cases.

### Core data

> **Note**
>
> The following documentation will be for SNARK proofs, as they are the only
> proofs that can be verified on our home chains.

The core data to be passed to any verification contract are the following:
- Verifying key: A unique key represented as 32 bytes, related to the program that is meant to be verified
- Public values: Serialized public values of the proof
- Proof: The serialized proof to be verified

**Verifying key**

The verifying key for a program at a given commit can be found in its fixture file
in the format of a hexified string prefixed by `0x`. There is [one file for the longest chain](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/solidity/contracts/src/plonk_fixtures/longest_chain_fixture.json)
program and one file for [the spv program](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/solidity/contracts/src/plonk_fixtures/spv_fixture.json).

**Public values**

The public values and serialized proof data can be found through the type [`SphinxProofWithPublicValues`](https://github.com/argumentcomputer/sphinx/blob/36f3f9072dc187612640e2725a2f7524cf2f2215/sdk/src/proof.rs#L21-L28)
returned as an HTTP response body by the prover.

The public values can be found under the `public_values` property and are already
represented as a `Buffer` which data are to be transmitted to the verifier contract.
In the fixture files we leverage in our codebase, the public values are represented
as a hexified string prefixed by `0x`.

**Proof**

The proof data to be passed to the verifier contract is the following:

| Name                 | Byte offset | Description                                                                                                                                                                                                                                                                          |
|----------------------|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Verifying key prefix | 0           | Prefix to the encoded proof, a 4 bytes value corresponding to the first 4 bytes of the verifying key.                                                                                                                                                                                |
| Encoded proof        | 4           | Encoded proof which value can be found in the returned SNARK proof from the prover represented as [`SphinxProofWithPublicValues`](https://github.com/argumentcomputer/sphinx/blob/36f3f9072dc187612640e2725a2f7524cf2f2215/sdk/src/proof.rs#L21-L28) under [`proof.encoded_proof`](https://github.com/argumentcomputer/sphinx/blob/dev/recursion/gnark-ffi/src/plonk_bn254.rs#L24) |

Example of the proof data extraction can be found [in our fixture generation crate](https://github.com/argumentcomputer/zk-light-clients/blob/dev/fixture-generator/src/bin/main.rs#L484).

### Wrapper logic

The wrapper logic refers to a smart contract wrapping the proof verification logic
with the use case specific logic. It is needed to ensure that the verified proof corresponds
to the expected data.

The logic to be executed in the wrapper contract will depend on the use case. However,
there are some core logic that have to be executed for the longest chain and spv proof 
verification. The logic that has to be kept for the inclusion verification
and the committee change program are showcased in our Solidity contracts ([longest chain](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/solidity/contracts/src/Wrapper.sol#L105) and [spv](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/solidity/contracts/src/Wrapper.sol#L117-L129)).

The place where a user can add its own use case logic is where we currently print out some values
for both the [longest chain](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/solidity/contracts/src/Wrapper.sol#L107) and [spv](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/solidity/contracts/src/Wrapper.sol#L131)).
