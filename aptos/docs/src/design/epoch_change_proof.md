# Epoch change proof

The Aptos consensus has (at any given time) a set of validators that are charged with executing blocks and sign them to
append them to the chain state.

A set of given validators is updated at the last block of every epoch on the chain. An **epoch on the Aptos chain has a
duration of 2 hours**. The light client needs to keep track of the hash of the current trusted validator set, which is
updated on every epoch change.

For a given epoch \\(N\\) with a set of validators \\(V_n\\), it is expected to have a block for the transition to
epoch \\(N+1\\) signed by \\(V_n\\) containing the new validator set \\(V_{\text{n+1}}\\).

It is the job of the light client to produce a proof at every epoch change to verify the signature on the validators for
the new epoch. This is handled by the Epoch Change program.

## Epoch Change program IO

[Program reference](https://github.com/lurk-lab/zk-light-clients/blob/dev/aptos/programs/epoch-change/src/main.rs)

### Inputs

The following data structures are required for proof generation (detailed data structure references can be found at the
end of this document):

- **Latest Known `TrustedState`**: The most recent known state, representing the trusted state for the current epoch.
    - **`ValidatorVerifier`:** Validator set information for epoch N, provided by the user.
- **`EpochChangeProof`**: Proof structure required to transition to the next epoch.
    - **`LedgerInfoWithSignatures`:** Signed ledger info that includes the new validator set for epoch N+1, provided by
      the user.

### Outputs

- **Previous `ValidatorVerifier` Hash:** The previous validator verifier hash, used for comparison.
- **Ratcheted `ValidatorVerifier` Hash:** The hash representing the new validator set for epoch N+1.
