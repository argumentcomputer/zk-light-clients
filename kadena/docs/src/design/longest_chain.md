# Longest chain proof

The light client needs to keep track of the longest chain to ensure that it is in 
sync with the running chain. The longest chain is the chain with the most accumulated
work.

There are a few predicates that need to be satisfied to ensure that the light client
is in sync with the longest chain:
1. The newly presented list of blocks supposed to represent the tip
    of the longest chain must be mined on top of an already verified layer block.
2. The height of each layer block must be strictly increasing.
3. The parent hash of each inner chain block headers must match the hash of the
    previous block of the given chain ID.
4. The work produced for a given chain block header must be inferior or equal
    to the current target set for the chain.
5. The list of blocks representing the new tip of the longest chain must contain a block
    with a threshold of work produced on top of it satisfying an arbitrary value set
    by the Light Client.
6. The chain block headers composing the layer block headers are properly braided,
    meaning that each chain block header contains information of their adjacent
    chain block headers.
7. If the one of the block in the list represents a new epoch, check that the difficulty
    adjustment is correct.

To ensure that the predicates 1. and 5. the Light Client verifier needs to keep track 
of the most recent verified layer block headers and an arbitrary security threshold to 
consider a block as the tip of the longest chain.

## Longest Chain program IO

[Program reference](https://github.com/argumentcomputer/zk-light-clients/blob/dev/kadena/programs/longest-chain/src/main.rs)

### Inputs

The following data structures are required for proof generation:

- Vector of **`LayerBlockHeader`**: A List of layer block headers that can be considered 
    as part of the longest chain.
  - Element at index 0: An already verified Layer Block Header.

### Outputs

- **`BigInt`**: U256 representing the total work produced on top of the newly verified block.
- **`HashValue`**: 32 bytes representing the hash of the first layer block header of the list.
- **`HashValue`**: 32 bytes representing the hash of the newly verified layer block header.