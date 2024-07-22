# Design of the Light Client

Light clients can be seen as lightweight nodes that enable users to interact with the blockchain without needing to
download the entire blockchain history. They **rely on full nodes to provide necessary data**, such as block headers,
and use cryptographic proofs to verify transactions and maintain security.

At the core of the LC there are two proofs:

- Prove epoch transition on the Aptos chain, which is effectively proving a transition from one set of validators to
  another one.
- Prove at any given point that an account is part of the Aptos state to provide the bridging capabilities between the
  Aptos and another blockchain.

<img src="../images/aptos-proofs.png">

This is implemented by two proofs, one for each statement. The light client needs to keep track of one hash that uniquely
identifies the latest known set of validators that it trusts. The first program is responsible for updating this hash,
whereas the second program makes use of this hash to identify a trusted validator set.

The first proof needs to be generated and submitted to the light client every 2 hours to ensure that the light client's
internal state is kept up to date with the running chain.

The second proof is generated and submitted when a proof about some on-chain value is required, for example when a deposit
to some account needs to be validated.

The current Verifying Key Hashes which uniquely identify the specific RISC-V binaries for the proof programs, located in the
[`aptos/aptos-programs/artifacts/`](https://github.com/lurk-lab/zk-light-clients/tree/dev/aptos/aptos-programs/artifacts)
directory are:
* `epoch_change`: `0x00eea0650222f7e5bb6a2fe57c0e0e504d1df8b3d848d5116174a8703d228c94`
* `inclusion`: `0x00336c570224c00161ca7b3c275c24f3968aa09086c31d09d98691bce109f4f6`

These values are also present in and used by the [solidity fixtures](../benchmark/on_chain.md).
