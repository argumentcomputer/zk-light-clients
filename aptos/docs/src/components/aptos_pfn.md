# Aptos Full Node

In the case of this particular Light Client, we will need to communicate with an Aptos Full Node to retrieve the
necessary data to prove the state of the chain. A deployed Aptos Public Full Node natively exposes RPC endpoints that
can be used to query the state of the chain.

However, the current codebase for an Aptos Full Node found
at [`aptos-labs/aptos-core`](https://github.com/aptos-labs/aptos-core) does not implement the necessary endpoints that
would allow us to retrieve the data we need. It is especially lacking when it comes to fetching data related to the
consensus layer, such as block header signatures.

To make up for that, we forked the repository into our
own [`lurk-lab/ptos-core`](https://github.com/lurk-lab/aptos-core). This forked repository should be the reference for
the Aptos Full Node until the core developer of the Aptos protocol have made the necessary update.

## RPC endpoints

The only updates made to the Aptos Full Node on our forks are meant to expose two new endpoints:

- `/v1/epoch/proof?epoch_number={:epoch}`: This endpoint can be used to get all the necessary data to generate a proof
  about an Epoch transition. Optionally, one can specify the epoch number to get the data for a specific epoch.
- `/v1/accounts/{:address}/proof?block_height={:height}`: The endpoint can be called to fetch data to prove the
  inclusion of the given `address` in the state of the chain. Optionally, one can specify the block height to get the
  data at the desired height.

### `/v1/epoch/proof`

#### 📨 Request Payload

- **Epoch number** *integer*

  The epoch number for which we want to get the data.

#### 📬 Response Payload

- **LedgerInfoWithSignature** *object*

  The signed ledger data for the block that triggered the epoch transition.

- **TrustedState** *object*

  A checkpoint of the state representing the validator list for the epoch preceding the one requested.

### `/v1/accoounts/{:address}/proof`

#### 📨 Request Payload

- **Account address** *string[hex]*

  Address of an account.

- **Block Height** *integer*

  Block height to check inclusion at.

#### 📬 Response Payload

- **SparseMerkleProof** *object*

  A data structure containing information to prove that a given account is part of a state resulting from a transaction.

- **Account state leaf key** *string[hex]*

  Path in the state Merkle Tree for the account leaf to the state root hash.

- **Account state leaf value** *string[hex]*

  Hashed value of the Account leaf.

- **TransactionAccumulatorProof** *object*

  A data structure containing information to prove that a transaction is part of the received **LedgerInfoWithSignature
  **

- **TransactionInfo** *object*

  Information about the transaction, notably the state root hash resulting from its execution.

- **Transaction index** *number*

  Index associated to the transaction in the accumulator.

- **LedgerInfoWithSignature** *object*

  The signed ledger data for the block at the given height.

- **ValidatorVerifier** *object*

  Committee in charge of block header signature when the `LedgerInfoWithSignatures` was produced.