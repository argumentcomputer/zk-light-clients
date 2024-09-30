# Design of the Light Client

Light clients can be seen as lightweight nodes that enable users to interact with the blockchain without needing to
download the entire blockchain history. They **rely on full nodes to provide necessary data**, such as block headers,
and use cryptographic proofs to verify transactions and maintain security.

> **Info**
>
> In the current implementation of the Light Client, we consider the whole Chainweb protocol
> as a single chain. This is a simplification that allows us to create the notion of
> _layer blocks_ as blocks containing the block headers for all the chains in the network
> at a given height.

At the core of the LC there are two proofs:

- Prove the current longest chain on top of the Chainweb Protocol to ensure that the light client is in sync with the
  running chain.
- Prove the verification for an SPV at the tip of the longest finalized chain to bridge a state transition.

This is implemented by two proofs, one for each statement. The light client verifier
needs to keep track of the most recent verified layer block headers to be able to
continuously verify on top of the longest chain. For security reasons, a threshold 
on the work to be produced on top of a layer block is set to ensure that the light client
is not tricked into verifying a chain that is not the longest chain.

We keep a list of the most recent layer block headers that have been verified by the light client
to handle forks that could happen on the Chainweb protocol.

The first proof needs to be generated to ensure that the light client is in sync with the longest chain.

The second proof is generated and submitted when a proof about some on-chain value is required, for example when a
deposit to some account needs to be validated. It has to be noted that it also ratchet the verifier 
state closer to the longest chain state.