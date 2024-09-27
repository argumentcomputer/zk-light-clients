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
- Prove the verification for an SPV at the tip of the longest chain to bridge a state transition.

This is implemented by two proofs, one for each statement. The light client verifier
needs to keep track of the latest verified layer block

The first proof needs to be generated and submitted to the light client at least every
54.6 hours to ensure that the light client's \\(N\\) internal state is kept up to date with the running chain.

The second proof is generated and submitted when a proof about some on-chain value is required, for example when a
deposit to some account needs to be validated.

The current Verifying Key Hashes which uniquely identify the specific RISC-V
binaries for the proof programs, located in the
[`ethereum/ethereum-programs/artifacts/`](https://github.com/argumentcomputer/zk-light-clients/tree/dev/ethereum/ethereum-programs/artifacts)
directory are:

* `epoch_change`: `0x0016ada2465cce37e1908bf462fec9c82d3f6f090965345d8f785f6d11f65826`
* `inclusion`: `0x006166fe4b4cad8e89f01bdaea9f54bd7476302ec74d45492058172a01342cea`

These values are also present in and used by the [move fixtures](../benchmark/on_chain.md).
