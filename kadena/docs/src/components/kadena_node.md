# Kadena Node

In order to generate the two proofs composing the Light Client, it is needed to 
fetch data from the Kadena network. To retrieve this data, the Light Client needs
to interact with a node from the Kadena chain.

## Kadena Full Node

The connection to a Kadena Full Node is necessary to access the endpoint
we require to fetch the data we use as input for our proofs. The following endpoints
are currently leverage:
- [`/header`](https://docs.kadena.io/reference/chainweb-api/blockheader#get-block-headersh-577852401): 
  Endpoint used to fetch the chain block headers that will be composing the layer block headers we want to generate a proof about.
- [`/payload/<PAYLOAD_HASH>/outputs`](https://docs.kadena.io/reference/chainweb-api/payload#get-block-payload-with-outputsh1850694017): 
  Endpoint used to fetch the request key for the transaction we want to verify an SPV about.
- [`/pact/spv`](https://docs.kadena.io/reference/rest-api#fetch-a-simple-payment-verification-spvh345444265): 
  Endpoint used to request an SPV about a particular transaction.
