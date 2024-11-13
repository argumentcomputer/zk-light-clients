# Design of the Light Client

Light clients can be seen as lightweight nodes that enable users to interact with the blockchain without needing to
download the entire blockchain history. They **rely on full nodes to provide necessary data**, such as block headers,
and use cryptographic proofs to verify transactions and maintain security.

At the core of the LC there are two proofs:

- Prove Sync Committee change on the Ethereum chain, which is effectively proving a transition from one set of
  validators to another one.
- Prove at any given point that an account is part of the Ethereum state to provide the bridging capabilities between
  Ethereum and another blockchain.

This is implemented by two proofs, one for each statement. The light client needs to keep track of two hashes that
uniquely identifies the latest known set of validators that it trusts and the one for the next period. The first
program is responsible for updating those hashes, whereas the second program makes
use of them to confirm the presence of a given account in the state.

The first proof needs to be generated and submitted to the light client at least every
54.6 hours to ensure that the light client's \\(N\\) internal state is kept up to date with the running chain.

The second proof is generated and submitted when a proof about some on-chain value is required, for example when a
deposit to some account needs to be validated.

The current Verifying Key Hashes which uniquely identify the specific RISC-V
binaries for the proof programs, located in the
[`ethereum/ethereum-programs/artifacts/`](https://github.com/argumentcomputer/zk-light-clients/tree/dev/ethereum/ethereum-programs/artifacts)
directory are:

* `epoch_change`: `0x00de53d6fe5e4e43f950fbc1f6b2c0f9c172097ad7263ab913241267b29d03f2`
* `inclusion`: `0x00deddfe90263f93c03e88dc9c33603f3ea0493b2af5da7e37d515794958bbb7`

These values are also present in and used by the [move fixtures](../benchmark/on_chain.md).
