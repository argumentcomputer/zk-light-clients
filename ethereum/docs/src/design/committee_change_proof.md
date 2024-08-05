# Sync committee change proof

The Ethereum chain has (at any given time) a committee of 512 validators that
is randomly selected every sync committee period (~1 day), and while a validator
is part of the currently active sync committee they are expected to continually
sign the block header that is the new head of the chain at each slot.

At the start of each period \\(N\\) any Light Client can trustfully know and verify
the current valid sync committee and the one for the period \\(N+1\\). The Light Client
needs to keep track of those two hashes.

For a given period \\(N\\) with a set of validators \\(V_n\\), it is expected to be able to
find a block containing information about the new validator set \\(V_{\text{n+1}}\\) signed by
\\(V_n\\).

It is the job of the light client to produce a proof at least every other period to
verify the signature for the next validator set. This is handled by the Sync
Committee Change program.

## Epoch Change program IO

[Program reference](https://github.com/argumentcomputer/zk-light-clients/blob/dev/ethereum/programs/committee-change/src/main.rs)

### Inputs

The following data structures are required for proof generation:

- **`LightClientStore`**: The current state of the Light Client, containing information about the latest handled finalized block and the known committees.
- **`Update`**: A Light Client update, containing information about a change of the Sync Committee.

### Outputs

- **Finalized header slot**: The slot of the finalized beacon header.
- **Hash of the signing sync committee**: The hash of the signing committee for the finalized beacon block.
- **Hash of the new sync committee**: The hash of the new sync committee set in the store.
- **Hash of the new sync committee for the next period**: The hash of the new sync committee for the following period set in the update.