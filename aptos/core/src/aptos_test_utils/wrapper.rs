//! This module provides a wrapper around the Aptos execution layer.
//! It includes utilities for creating and interacting with a simulated Aptos blockchain.
//! It is primarily used for testing purposes.

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::aptos_test_utils::error::AptosError;
use aptos_crypto::bls12381::Signature;
use aptos_crypto::hash::{CryptoHash, TransactionAccumulatorHasher};
use aptos_crypto::HashValue;
use aptos_executor::block_executor::BlockExecutor;
use aptos_executor_test_helpers::gen_block_id;
use aptos_executor_test_helpers::integration_test_impl::create_db_and_executor;
use aptos_executor_types::BlockExecutorTrait;
use aptos_sdk::transaction_builder::aptos_stdlib::version_set_version;
use aptos_sdk::transaction_builder::{aptos_stdlib, TransactionFactory};
use aptos_sdk::types::{AccountKey, LocalAccount};
use aptos_storage_interface::DbReaderWriter;
use aptos_types::account_config::{aptos_test_root_address, AccountResource};
use aptos_types::aggregate_signature::PartialSignatures;
use aptos_types::block_info::BlockInfo;
use aptos_types::block_metadata::BlockMetadata;
use aptos_types::chain_id::ChainId;
use aptos_types::ledger_info::LedgerInfoWithSignatures;
use aptos_types::proof::{AccumulatorProof, SparseMerkleProof};
use aptos_types::state_proof::StateProof;
use aptos_types::state_store::state_key::StateKey;
use aptos_types::state_store::state_value::StateValue;
use aptos_types::test_helpers::transaction_test_helpers::{
    block, TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
};
use aptos_types::transaction::signature_verified_transaction::SignatureVerifiedTransaction;
use aptos_types::transaction::Transaction::UserTransaction;
use aptos_types::transaction::{Transaction, TransactionInfo, WriteSetPayload};
use aptos_types::trusted_state::{TrustedState, TrustedStateChange};
use aptos_types::validator_signer::ValidatorSigner;
use aptos_types::validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier};
use aptos_vm::AptosVM;
use aptos_vm_genesis::TestValidator;
use getset::Getters;
use move_core_types::account_address::AccountAddress;
use move_core_types::move_resource::MoveStructType;
use rand::prelude::SliceRandom;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Multiplier to fund accounts, so that they can interact with the chain without
/// worrying about it.
const BALANCE_MUILTIPLIER: u64 = 1_000_000_000;

/// Structure containing a `SparseMerkleProof` for and account, along with the parameters to verify it.
#[derive(Getters, Clone, Debug, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct SparseMerkleProofAssets {
    /// Proof for the account inclusion
    state_proof: SparseMerkleProof,
    /// Account leaf key
    key: HashValue,
    /// Account state value
    state_value: Option<StateValue>,
    /// Root hash of the tree including the account
    root_hash: HashValue,
    /// Proof for the transaction inclusion
    transaction_proof: AccumulatorProof<TransactionAccumulatorHasher>,
    /// Hashed representation of the transaction
    transaction: TransactionInfo,
    /// Transaction version
    transaction_version: u64,
}

impl SparseMerkleProofAssets {
    /// Verify the proof against the root hash
    pub fn state_value_hash(&self) -> Result<HashValue, AptosError> {
        self.state_value
            .as_ref()
            .map(|sv| sv.hash())
            .ok_or(AptosError::UnexpectedNone("state_value".to_string()))
    }
}

/// Wrapper around the Aptos execution layer for testing purposes.
///
/// This struct provides methods for creating a simulated Aptos blockchain,
/// executing transactions, and querying the state of the blockchain.
#[derive(Getters)]
#[getset(get = "pub")]
#[allow(dead_code)]
pub struct AptosWrapper {
    /// Admin account for the chain, in charge of creating new accounts, reconfiguration...
    core_resources_account: LocalAccount,
    /// Available accounts to interact with the chain
    accounts: Vec<LocalAccount>,
    /// Validators of the chain
    validators: Vec<TestValidator>,
    /// Signer's account for validators
    signers: Vec<ValidatorSigner>,
    /// Number of signers per block produced
    signers_per_block: usize,
    /// Transaction factory to generate transactions
    txn_factory: TransactionFactory,
    /// Database for the chain
    db: DbReaderWriter,
    /// Executor to commit new block to the chain
    executor: BlockExecutor<AptosVM>,
    /// Current trusted state for the chain
    trusted_state: TrustedState,
    /// Current epoch
    current_epoch: u64,
    /// Current round for the epoch
    current_round: u64,
    /// Current version
    current_version: u64,
    /// Current block
    current_block: usize,
    /// Mock major version of the chain
    major_version: u64,
}

/// Enum that represent arguments to execute a block. Either the
/// `StateProof` is generated, and we can use it, otherwise generate
/// it from the block id and the block transactions.
pub enum ExecuteBlockArgs {
    /// Use the provided `StateProof`
    StateProof(Box<StateProof>),
    /// Generate the `StateProof` from the block id and transactions
    Block(HashValue, Vec<SignatureVerifiedTransaction>),
}

#[allow(dead_code)]
impl AptosWrapper {
    /// Creates a new instance of the AptosWrapper with a specified number of local accounts, validators, and signers per block.
    ///
    /// # Arguments
    ///
    /// * `nbr_local_accounts` - The number of local accounts to create.
    /// * `nbr_validators` - The number of validators to create.
    /// * `signers_per_block` - The number of signers per block.
    ///
    /// # Returns
    ///
    /// * `Self` - A new instance of the AptosWrapper.
    pub fn new(
        nbr_local_accounts: usize,
        nbr_validators: usize,
        signers_per_block: usize,
    ) -> Result<Self, AptosError> {
        // Create temporary location for the database
        let path = aptos_temppath::TempPath::new();
        path.create_as_dir()
            .map_err(|e| AptosError::FileSystem { source: e })?;
        // Create a test genesis and some validator for our test chain
        let (genesis, validators) =
            aptos_vm_genesis::test_genesis_change_set_and_validators(Some(nbr_validators));
        // Define admin account
        let genesis_txn = Transaction::GenesisTransaction(WriteSetPayload::Direct(genesis));
        let core_resources_account: LocalAccount = LocalAccount::new(
            aptos_test_root_address(),
            AccountKey::from_private_key(aptos_vm_genesis::GENESIS_KEYPAIR.0.clone()),
            0,
        );

        // Create a database, executor and waypoint. We use a default db, not a sharding one.
        let (_, db, executor, waypoint) = create_db_and_executor(path.path(), &genesis_txn, false);

        // Set current signer as the first validator
        let signers = validators
            .iter()
            .map(|v| ValidatorSigner::new(v.data.owner_address, v.consensus_key.clone()))
            .collect();
        // Generate accounts
        let accounts = generate_local_accounts(nbr_local_accounts);
        // Transaction factory
        let txn_factory = TransactionFactory::new(ChainId::test());

        let mut aptos_wrapper = Self {
            core_resources_account,
            accounts,
            validators,
            signers_per_block,
            signers,
            txn_factory,
            db,
            executor,
            trusted_state: TrustedState::from_epoch_waypoint(waypoint),
            current_epoch: 1,
            current_round: 1,
            current_version: 1,
            current_block: 1,
            major_version: 100,
        };

        aptos_wrapper.fund_accounts()?;

        Ok(aptos_wrapper)
    }

    /// Funds the given accounts with some coins, effectively committing a new block on the chain.
    ///
    /// This method generates a block with transactions that fund each account and then executes the block.
    // TODO assume that accounts were not previously created so we always try to create them, could be nice to change in the future
    fn fund_accounts(&mut self) -> Result<(), AptosError> {
        let (block_id, block_meta) = self.gen_block_id_and_metadata();
        let mut block_txs = vec![block_meta];
        for account in self.accounts() {
            let create_tx = self.core_resources_account().sign_with_transaction_builder(
                self.txn_factory().create_user_account(account.public_key()),
            );
            block_txs.push(UserTransaction(create_tx));
            let fund_tx = self.core_resources_account().sign_with_transaction_builder(
                self.txn_factory()
                    .mint(account.address(), 1_000 * BALANCE_MUILTIPLIER),
            );
            block_txs.push(UserTransaction(fund_tx));
        }

        self.execute_block(ExecuteBlockArgs::Block(block_id, block(block_txs)))
    }

    /// Prepares the ratcheting process by executing a block and saving it to persistent storage.
    ///
    /// # Arguments
    ///
    /// * `block_id` - The ID of the block to be executed.
    /// * `block` - The transactions to be included in the block.
    /// * `from_version` - The version from which to start the ratcheting process.
    ///
    /// # Returns
    ///
    /// * `StateProof` - The state proof for the executed block.
    fn prepare_ratcheting(
        &mut self,
        block_id: HashValue,
        block: &[SignatureVerifiedTransaction],
        from_version: u64,
    ) -> Result<StateProof, AptosError> {
        let output = self
            .executor()
            .execute_block(
                (block_id, block.to_owned()).into(),
                self.executor().committed_block_id(),
                TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
            )
            .map_err(|e| AptosError::Internal { source: e.into() })?;

        let ledger_info = aptos_types::ledger_info::LedgerInfo::new(
            BlockInfo::new(
                *self.current_epoch(),
                0, /* round */
                block_id,
                output.root_hash(),
                output.version(),
                0, /* timestamp */
                output.epoch_state().clone(),
            ),
            HashValue::zero(),
        );

        let partial_sig = PartialSignatures::new(
            self.signers()
                .get(..self.signers_per_block)
                .ok_or(AptosError::UnexpectedNone("ValidatorSigner".to_string()))?
                .iter()
                .map(|signer| {
                    signer
                        .sign(&ledger_info)
                        .map_err(|e| AptosError::Internal { source: e.into() })
                        .map(|s| (signer.author(), s))
                })
                .collect::<Result<BTreeMap<AccountAddress, Signature>, AptosError>>()?,
        );

        let validator_consensus_info = self
            .signers()
            .iter()
            .map(|signer| ValidatorConsensusInfo::new(signer.author(), signer.public_key(), 1))
            .collect();

        let validator_verifier = ValidatorVerifier::new_with_quorum_voting_power(
            validator_consensus_info,
            self.signers_per_block as u128,
        )
        .expect("Incorrect quorum size.");

        let li = LedgerInfoWithSignatures::new(
            ledger_info,
            validator_verifier
                .aggregate_signatures(&partial_sig)
                .map_err(|e| AptosError::Internal { source: e.into() })?,
        );

        // Save block to persistent storage
        self.executor()
            .commit_blocks(vec![block_id], li)
            .map_err(|e| AptosError::Internal { source: e.into() })?;

        self.db()
            .reader
            .get_state_proof(from_version)
            .map_err(|e| AptosError::Internal { source: e.into() })
    }

    /// Generates a new state proof for a given version.
    ///
    /// # Arguments
    ///
    /// * `from_version` - The version for which to generate the state proof.
    ///
    /// # Returns
    ///
    /// * `StateProof` - The generated state proof for the given version.
    pub fn new_state_proof(&mut self, from_version: u64) -> Result<StateProof, AptosError> {
        let (block_id, block_meta) = self.gen_block_id_and_metadata();
        let mut block_txs = vec![block_meta];
        let new_version = *self.major_version() + 100;
        let reconfig = self.core_resources_account().sign_with_transaction_builder(
            self.txn_factory().payload(version_set_version(new_version)),
        );
        block_txs.push(UserTransaction(reconfig));
        let end_epoch = self.core_resources_account().sign_with_transaction_builder(
            self.txn_factory()
                .payload(aptos_stdlib::aptos_governance_force_end_epoch_test_only()),
        );
        block_txs.push(UserTransaction(end_epoch));

        self.major_version = new_version;

        self.prepare_ratcheting(block_id, &block(block_txs), from_version)
    }

    /// Executes a new block and updates necessary properties.
    ///
    /// The `StateProof` for the ratcheting can either be passed from an external source
    /// or generated internally.
    ///
    /// # Arguments
    ///
    /// * `execution_arguments` - The arguments for block execution, either a `StateProof` or a block ID and transactions.
    ///
    /// # Panics
    ///
    /// This method panics if the trusted state fails to verify and ratchet the state proof.
    pub fn execute_block(
        &mut self,
        execution_arguments: ExecuteBlockArgs,
    ) -> Result<(), AptosError> {
        let state_proof = match execution_arguments {
            ExecuteBlockArgs::StateProof(state_proof) => *state_proof,
            ExecuteBlockArgs::Block(block_id, block) => {
                self.prepare_ratcheting(block_id, &block, self.trusted_state.version())?
            }
        };

        // Ratchet trusted state to latest version
        let trusted_state = match self.trusted_state().verify_and_ratchet(&state_proof) {
            Ok(TrustedStateChange::Epoch { new_state, .. }) => {
                match &new_state {
                    TrustedState::EpochState { epoch_state, .. } => {
                        if self.current_epoch != epoch_state.epoch {
                            self.current_round = 1;
                        }
                        self.current_epoch = epoch_state.epoch;
                    }
                    _ => return Err(AptosError::TrustedStageChange {
                        source: "Expected new state as TrustedState::EpochState for TrustedStateChange::Epoch".into()
                    }),
                }

                new_state
            }
            Ok(TrustedStateChange::Version { new_state, .. }) => {
                self.current_round += 1;
                new_state
            }
            Err(err) => return Err(AptosError::TrustedStageChange { source: err.into() }),
            _ => {
                return Err(AptosError::TrustedStageChange {
                    source: "Expected TrustedState::EpochState".into(),
                })
            }
        };

        // Ensure ratcheting worked well
        let latest_li = state_proof.latest_ledger_info();
        let current_version = latest_li.version();
        assert_eq!(trusted_state.version(), current_version);

        self.trusted_state = trusted_state;
        self.current_block += 1;
        self.current_version = current_version;

        Ok(())
    }

    /// Generates a block ID and metadata for the next block.
    ///
    /// # Returns
    ///
    /// * `(HashValue, Transaction)` - A tuple containing the block ID and the block metadata transaction.
    fn gen_block_id_and_metadata(&self) -> (HashValue, Transaction) {
        let block_id = gen_block_id(self.current_block as u8);
        let block_meta = Transaction::BlockMetadata(BlockMetadata::new(
            block_id,
            self.current_epoch,
            self.current_round,
            self.signers[0].author(),
            vec![0],
            vec![],
            self.current_block as u64,
        ));
        (block_id, block_meta)
    }

    /// Creates some random transfers between the accounts of the chain and executes them in a block.
    ///
    /// This method generates a block with transactions that transfer a small amount of coins between random accounts,
    /// and then executes the block. It is used to simulate traffic in the blockchain for testing purposes.
    ///
    /// # Note
    ///
    /// This method only transfers small amounts to ensure there is no gas issue. However, calling this method too frequently
    /// could result in transactions not passing due to insufficient funds.
    pub fn generate_traffic(&mut self) -> Result<(), AptosError> {
        let (block_id, block_meta) = self.gen_block_id_and_metadata();
        let mut block_txs = vec![block_meta];
        for _ in 0..10 {
            let sender = self
                .accounts()
                .choose(&mut rand::thread_rng())
                .ok_or(AptosError::UnexpectedNone("random sender".to_string()))?;
            let mut receiver = self
                .accounts()
                .choose(&mut rand::thread_rng())
                .ok_or(AptosError::UnexpectedNone("random receiver".to_string()))?;

            // Ensure receiver is different from sender
            while receiver.address() == sender.address() {
                receiver = self
                    .accounts()
                    .choose(&mut rand::thread_rng())
                    .ok_or(AptosError::UnexpectedNone("random receiver".to_string()))?;
            }

            let transfer_tx = sender
                .sign_with_transaction_builder(self.txn_factory().transfer(receiver.address(), 10));
            block_txs.push(UserTransaction(transfer_tx));
        }
        self.execute_block(ExecuteBlockArgs::Block(block_id, block(block_txs)))
    }

    /// Commits a new epoch by executing a block with a reconfiguration transaction.
    ///
    /// This method increments the major version, executes a block with a reconfiguration transaction,
    /// and updates the current epoch, round, and version.
    pub fn commit_new_epoch(&mut self) -> Result<(), AptosError> {
        let (block_id, block_meta) = self.gen_block_id_and_metadata();
        let mut block_txs = vec![block_meta];
        let new_version = *self.major_version() + 100;
        let reconfig = self.core_resources_account().sign_with_transaction_builder(
            self.txn_factory()
                .payload(aptos_stdlib::version_set_for_next_epoch(new_version)),
        );
        block_txs.push(UserTransaction(reconfig));
        let end_epoch = self.core_resources_account().sign_with_transaction_builder(
            self.txn_factory()
                .payload(aptos_stdlib::aptos_governance_force_end_epoch_test_only()),
        );
        block_txs.push(UserTransaction(end_epoch));
        self.major_version = new_version;
        self.execute_block(ExecuteBlockArgs::Block(block_id, block(block_txs)))
    }

    /// Returns the latest `LedgerInfoWithSignatures` generated while executing a block.
    ///
    /// # Returns
    ///
    /// * `Result<LedgerInfoWithSignatures>` - The latest `LedgerInfoWithSignatures` if it exists.
    pub fn get_latest_li(&self) -> Result<LedgerInfoWithSignatures, AptosError> {
        self.db()
            .reader
            .get_latest_ledger_info_option()
            .map_err(|e| AptosError::Internal { source: e.into() })?
            .ok_or(AptosError::UnexpectedNone(
                "get_latest_ledger_info".to_string(),
            ))
    }

    /// Returns the latest `LedgerInfoWithSignatures` generated while executing a block, serialized with bcs.
    ///
    /// # Returns
    ///
    /// * `Option<Vec<u8>>` - The latest `LedgerInfoWithSignatures` serialized into bytes if it exists, `None` otherwise.
    pub fn get_latest_li_bytes(&self) -> Result<Vec<u8>, AptosError> {
        bcs::to_bytes(&self.get_latest_li()?).map_err(|e| AptosError::Serialization {
            structure: "LedgerInfoWithSignatures".to_string(),
            source: e.into(),
        })
    }

    /// Returns a `SparseMerkleProofAssets` for a specified account.
    ///
    /// # Arguments
    ///
    /// * `account_idx` - The index of the account for which to get the `SparseMerkleProofAssets`.
    ///
    /// # Returns
    ///
    /// * `Option<SparseMerkleProofAssets>` - The `SparseMerkleProofAssets` for the specified account if it exists, `None` otherwise.
    pub fn get_latest_proof_account(
        &self,
        account_idx: usize,
    ) -> Result<SparseMerkleProofAssets, AptosError> {
        // Create a state key to get the info
        let account_0_resource_path = StateKey::resource(
            &self
                .accounts()
                .get(account_idx)
                .ok_or(AptosError::UnexpectedNone("get accounts".into()))?
                .address(),
            &AccountResource::struct_tag(),
        )
        .map_err(|e| AptosError::Internal { source: e.into() })?;

        // Get the state proof for the current version
        let (state_value, state_proof) = self
            .db()
            .reader
            .get_state_value_with_proof_by_version(
                &account_0_resource_path,
                *self.current_version(),
            )
            .map_err(|e| AptosError::Internal { source: e.into() })?;

        // Get the transaction with proof for the current version
        let txn_w_proof = self
            .db()
            .reader
            .get_transaction_by_version(*self.current_version(), *self.current_version(), false)
            .map_err(|e| AptosError::Internal { source: e.into() })?;

        let transaction_version = txn_w_proof.version;
        let txn_info = txn_w_proof.proof.transaction_info;
        let ledger_info_to_transaction_info_proof =
            txn_w_proof.proof.ledger_info_to_transaction_info_proof;

        Ok(SparseMerkleProofAssets {
            state_proof,
            key: account_0_resource_path.hash(),
            state_value,
            root_hash: txn_info
                .state_checkpoint_hash()
                .ok_or(AptosError::UnexpectedNone(
                    "state_checkpoint_hash".to_string(),
                ))?,
            transaction_proof: ledger_info_to_transaction_info_proof,
            transaction: txn_info,
            transaction_version,
        })
    }
}

/// Generates a specified number of local accounts.
///
/// This function creates a new random number generator with a fixed seed, and then generates the specified number of local accounts.
///
/// # Arguments
///
/// * `n` - The number of local accounts to generate.
///
/// # Returns
///
/// * `Vec<LocalAccount>` - A vector of the generated local accounts.
fn generate_local_accounts(n: usize) -> Vec<LocalAccount> {
    let seed = [3u8; 32];
    let mut rng = ::rand::rngs::StdRng::from_seed(seed);

    (0..n)
        .map(|_| LocalAccount::generate(&mut rng))
        .collect::<Vec<LocalAccount>>()
}

#[test]
fn test_aptos_wrapper() {
    let mut aptos_wrapper = AptosWrapper::new(4, 1, 1).unwrap();

    // Get the state proof for the current version
    let state_proof_assets = aptos_wrapper.get_latest_proof_account(0).unwrap();
    state_proof_assets
        .state_proof()
        .verify(
            *state_proof_assets.root_hash(),
            *state_proof_assets.key(),
            state_proof_assets.state_value.as_ref(),
        )
        .unwrap();

    aptos_wrapper.generate_traffic().unwrap();
    assert_eq!(aptos_wrapper.trusted_state().version(), 22);

    assert_eq!(*aptos_wrapper.current_epoch(), 1);
    assert_eq!(*aptos_wrapper.major_version(), 100);
    assert_eq!(*aptos_wrapper.current_round(), 2);

    aptos_wrapper.commit_new_epoch().unwrap();

    assert_eq!(*aptos_wrapper.major_version(), 200);
    assert_eq!(*aptos_wrapper.current_epoch(), 2);
    assert_eq!(*aptos_wrapper.current_round(), 1);
    assert_eq!(aptos_wrapper.trusted_state().version(), 25);

    aptos_wrapper.generate_traffic().unwrap();
    assert_eq!(*aptos_wrapper.current_version(), 37)
}

#[test]
fn test_multiple_signers() {
    let mut aptos_wrapper = AptosWrapper::new(4, 15, 15).unwrap();

    // Get the state proof for the current version
    let state_proof_assets = aptos_wrapper.get_latest_proof_account(0).unwrap();
    state_proof_assets
        .state_proof()
        .verify(
            *state_proof_assets.root_hash(),
            *state_proof_assets.key(),
            state_proof_assets.state_value.as_ref(),
        )
        .unwrap();

    aptos_wrapper.generate_traffic().unwrap();
    assert_eq!(aptos_wrapper.trusted_state().version(), 22);
}
