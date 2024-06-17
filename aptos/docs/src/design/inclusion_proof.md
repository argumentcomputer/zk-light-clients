# Inclusion proof

To bridge an account from the Aptos chain to the Ethereum chain at any given time the LC needs to prove that the given
account exists in the chain state for the latest block produced.

To do so, the Light Client will first need to verify that the signature on the latest block corresponds to the validator
list known for the current epoch. Then, it will have to prove that the account is part of the updated state that this
block commits.

## Inclusion program IO

[Program reference](https://github.com/lurk-lab/zk-light-clients/blob/dev/aptos/programs/inclusion/src/main.rs)

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

- **Previous `ValidatorVerifier` Hash:** The previous validator verifier hash, used to validate the incoming data.
- **State Root Hash:** The root hash of the state, derived from the `TransactionInfo::state_checkpoint`.