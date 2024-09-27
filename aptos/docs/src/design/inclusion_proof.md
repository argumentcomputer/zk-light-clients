# Inclusion proof

To bridge an account from the Aptos chain to another chain at any given time the LC needs to prove that the given
account exists in the chain state for the latest block produced, with a given balance.

To do so, the Light Client will first need to verify that the signature on the latest block corresponds to the validator
list known for the current epoch. Then, it will have to prove that the account is part of the updated state that this
block commits.

The inclusion program takes in an arbitrary Aptos `SparseMerkleProof`, so it can represent inclusion of any kind of state
inside of the Aptos blockchain's state root. We have implemented a proof that checks that a given account key has a certain
balance, but this can be adapted to different scenarios without changing the inclusion program. See the
[Aptos PFN](../components/aptos_pfn.html) section of the documentation for more information on the code responsible for
building the `SparseMerkleProof`.

## Inclusion program IO

[Program reference](https://github.com/argumentcomputer/zk-light-clients/blob/dev/aptos/programs/inclusion/src/main.rs)

### Inputs

The following data structures are required for proof generation (detailed data structure references can be found at the
end of this document):

- **Block Validation**
    - **Latest `LedgerInfoWithSignatures`:** Contains the signed ledger info that acts as a root of trust for the
      current epoch.
    - **`ValidatorVerifier`:** The verifier set for the current epoch.
- **Merkle Inclusion**
    - **Transaction Inclusion in `LedgerInfo`:** Verifies that the specified transaction exists in the block with a
      valid state checkpoint.
        - **`TransactionInfo`:** Details of the transaction to be verified.
        - **Transaction Index in Block:** Position of the transaction within the block.
        - **`TransactionAccumulatorProof`:** Accumulator proof that confirms the transaction’s inclusion.
        - **Latest `LedgerInfoWithSignatures`:** Acts as a root of trust.
    - **Account Inclusion in State Checkpoint:** Verifies that the account exists in the blockchain’s state at the block
      level.
        - **`SparseMerkleProof`:** Proof that the account is included in the state.
        - **Account Key in Tree:** Path of the account within the Merkle tree.
        - **Value Hash for Account Leaf:** Initial hash used for inclusion verification.

### Outputs

- **Current `ValidatorVerifier` Hash:** The current validator verifier hash, used to validate the incoming data.
- **State Root Hash:** The root hash of the state, derived from the `TransactionInfo::state_checkpoint`.
- **Unique Block Identifier:** The identifier of the current block.
- **Merkle-tree key:** The key that identifies the place/position of the leaf being checked for in the merkle tree.
- **Merkle-tree value:** The hash of the actual value at the position of the merkle tree leaf.
