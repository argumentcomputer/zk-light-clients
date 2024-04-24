// SPDX-License-Identifier: Apache-2.0, MIT
use aptos_crypto::hash::CryptoHash;
use aptos_crypto::HashValue;
use aptos_executor::block_executor::BlockExecutor;
use aptos_executor_test_helpers::gen_block_id;
use aptos_executor_test_helpers::integration_test_impl::create_db_and_executor;
use aptos_executor_types::BlockExecutorTrait;
use aptos_sdk::transaction_builder::aptos_stdlib::version_set_version;
use aptos_sdk::transaction_builder::TransactionFactory;
use aptos_sdk::types::{AccountKey, LocalAccount};
use aptos_storage_interface::DbReaderWriter;
use aptos_types::access_path::AccessPath;
use aptos_types::account_config::{aptos_test_root_address, AccountResource};
use aptos_types::aggregate_signature::PartialSignatures;
use aptos_types::block_info::BlockInfo;
use aptos_types::block_metadata::BlockMetadata;
use aptos_types::chain_id::ChainId;
use aptos_types::ledger_info::LedgerInfoWithSignatures;
use aptos_types::proof::SparseMerkleProof;
use aptos_types::state_proof::StateProof;
use aptos_types::state_store::state_key::StateKey;
use aptos_types::state_store::state_value::StateValue;
use aptos_types::test_helpers::transaction_test_helpers::{
    block, TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
};
use aptos_types::transaction::signature_verified_transaction::SignatureVerifiedTransaction;
use aptos_types::transaction::Transaction::UserTransaction;
use aptos_types::transaction::{Transaction, WriteSetPayload};
use aptos_types::trusted_state::{TrustedState, TrustedStateChange};
use aptos_types::validator_signer::ValidatorSigner;
use aptos_types::validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier};
use aptos_vm::AptosVM;
use aptos_vm_genesis::TestValidator;
use getset::Getters;
use move_core_types::move_resource::MoveStructType;
use rand::prelude::SliceRandom;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

const BALANCE_MUILTIPLIER: u64 = 1_000_000_000;

/// Structure containing a `SparseMerkleProof` for and account, along with the parameters to verify it.
#[derive(Getters, Clone, Debug, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct SparseMerkleProofAssets {
    /// Proof for the account inclusion
    state_proof: SparseMerkleProof,
    /// Accout leaf key
    key: HashValue,
    /// Account state value
    state_value: Option<StateValue>,
    /// Root hash of the tree including the accout
    root_hash: HashValue,
}

impl SparseMerkleProofAssets {
    /// Verify the proof against the root hash
    pub fn state_value_hash(&self) -> HashValue {
        self.state_value.as_ref().unwrap().hash()
    }
}

/// Wrapper atound aptos execution layer to get data out of it.
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
    /// Latest `LedgerInfoWithSignature` generated while executing a block
    latest_li: Option<LedgerInfoWithSignatures>,
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

#[allow(dead_code)]
impl AptosWrapper {
    /// Create a new instance of the wrapper with n accounts. Will commit a first block to fund
    /// the accounts with some coins.
    pub fn new(nbr_local_accounts: usize, nbr_validators: usize, signers_per_block: usize) -> Self {
        // Create temporary location for the database
        let path = aptos_temppath::TempPath::new();
        path.create_as_dir().unwrap();
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
            latest_li: None,
            current_epoch: 1,
            current_round: 1,
            current_version: 1,
            current_block: 1,
            major_version: 100,
        };

        aptos_wrapper.fund_accounts();

        aptos_wrapper
    }

    /// Funds the given accounts with some coins, effectively committing a new block on the chain.
    // TODO assume that accounts were not previously created so we always try to create them, could be nice to change in the future
    fn fund_accounts(&mut self) {
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

        self.execute_block(block_id, &block(block_txs));
    }

    fn prepare_ratcheting(
        &mut self,
        block_id: HashValue,
        block: &[SignatureVerifiedTransaction],
        from_version: u64,
    ) -> StateProof {
        let output = self
            .executor()
            .execute_block(
                (block_id, block.to_owned()).into(),
                self.executor().committed_block_id(),
                TEST_BLOCK_EXECUTOR_ONCHAIN_CONFIG,
            )
            .unwrap();

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
                .unwrap()
                .iter()
                .map(|signer| (signer.author(), signer.sign(&ledger_info).unwrap()))
                .collect(),
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
                .unwrap(),
        );
        self.latest_li = Some(li.clone());

        // Save block to persistent storage
        self.executor().commit_blocks(vec![block_id], li).unwrap();

        self.db().reader.get_state_proof(from_version).unwrap()
    }

    pub fn new_state_proof(&mut self, from_version: u64) -> StateProof {
        let (block_id, block_meta) = self.gen_block_id_and_metadata();
        let mut block_txs = vec![block_meta];
        let new_version = *self.major_version() + 100;
        let reconfig = self.core_resources_account().sign_with_transaction_builder(
            self.txn_factory().payload(version_set_version(new_version)),
        );
        block_txs.push(UserTransaction(reconfig));
        self.major_version = new_version;

        self.prepare_ratcheting(block_id, &block(block_txs), from_version)
    }

    /// Execute a new block and updates necessary properties
    fn execute_block(&mut self, block_id: HashValue, block: &[SignatureVerifiedTransaction]) {
        let state_proof = self.prepare_ratcheting(block_id, block, self.trusted_state.version());
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
                    _ => {
                        panic!("should not happen")
                    }
                }

                new_state
            }
            Ok(TrustedStateChange::Version { new_state, .. }) => {
                self.current_round += 1;
                new_state
            }
            Err(err) => {
                panic!("ended with error: {:?}", err)
            }
            _ => {
                panic!("unexpected state change")
            }
        };

        // Ensure ratcheting worked well
        let latest_li = state_proof.latest_ledger_info();
        let current_version = latest_li.version();
        assert_eq!(trusted_state.version(), current_version);

        self.trusted_state = trusted_state;
        self.current_block += 1;
        self.current_version = current_version;
    }

    /// Generate block id and metadata for the next block.
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

    /// Create some random transfers between the accounts of the chain and execute them in a block.
    // TODO, we only transfer small amounts to ensure there is no gas issue but calling this too much would result on tx not passing
    pub fn generate_traffic(&mut self) {
        let (block_id, block_meta) = self.gen_block_id_and_metadata();
        let mut block_txs = vec![block_meta];
        for _ in 0..10 {
            let sender = self.accounts().choose(&mut rand::thread_rng()).unwrap();
            let mut receiver = self.accounts().choose(&mut rand::thread_rng()).unwrap();

            // Ensure receiver is different from sender
            while receiver.address() == sender.address() {
                receiver = self.accounts().choose(&mut rand::thread_rng()).unwrap();
            }

            let transfer_tx = sender
                .sign_with_transaction_builder(self.txn_factory().transfer(receiver.address(), 10));
            block_txs.push(UserTransaction(transfer_tx));
        }
        self.execute_block(block_id, &block(block_txs));
    }

    pub fn commit_new_epoch(&mut self) {
        let (block_id, block_meta) = self.gen_block_id_and_metadata();
        let mut block_txs = vec![block_meta];
        let new_version = *self.major_version() + 100;
        let reconfig = self.core_resources_account().sign_with_transaction_builder(
            self.txn_factory().payload(version_set_version(new_version)),
        );
        block_txs.push(UserTransaction(reconfig));
        self.major_version = new_version;
        self.execute_block(block_id, &block(block_txs));
    }

    /// Get latest `LedgerInfoWithSignatures` generated while executing a block
    pub fn get_latest_li(&self) -> Option<LedgerInfoWithSignatures> {
        self.latest_li.clone()
    }
    /// Same as `get_latest_li` but with returned payload as bytes, serialized with bcs
    pub fn get_latest_li_bytes(&self) -> Option<Vec<u8>> {
        Some(
            bcs::to_bytes(&self.get_latest_li()?)
                .expect("LedgerInfoWithSignatures serialization failed"),
        )
    }

    /// Get latest `LedgerInfoWithSignatures` generated while executing a block
    pub fn get_latest_proof_account(&self, account_idx: usize) -> Option<SparseMerkleProofAssets> {
        // Create a state key to get the info
        let account_0_resource_path = StateKey::access_path(AccessPath::new(
            self.accounts().get(account_idx)?.address(),
            AccountResource::struct_tag().access_vector(),
        ));
        // Get the state proof for the current version
        let (state_value, state_proof) = self
            .db()
            .reader
            .get_state_value_with_proof_by_version(
                &account_0_resource_path,
                *self.current_version(),
            )
            .unwrap();

        let txn_info = self
            .db()
            .reader
            .get_transaction_info_iterator(*self.current_version(), 1)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        Some(SparseMerkleProofAssets {
            state_proof,
            key: account_0_resource_path.hash(),
            state_value,
            root_hash: txn_info.state_checkpoint_hash().unwrap(),
        })
    }
    /// Same as `get_latest_li` but with returned payload as bytes, serialized with bcs
    pub fn get_latest_proof_account_bytes(&self, account_idx: usize) -> Option<Vec<u8>> {
        Some(
            bcs::to_bytes(&self.get_latest_proof_account(account_idx)?)
                .expect("LedgerInfoWithSignatures serialization failed"),
        )
    }
}

/// Generates some accounts to interact with the chain.
fn generate_local_accounts(n: usize) -> Vec<LocalAccount> {
    let seed = [3u8; 32];
    let mut rng = ::rand::rngs::StdRng::from_seed(seed);

    (0..n)
        .map(|_| LocalAccount::generate(&mut rng))
        .collect::<Vec<LocalAccount>>()
}

#[test]
fn test_aptos_wrapper() {
    let mut aptos_wrapper = AptosWrapper::new(4, 1, 1);

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

    aptos_wrapper.generate_traffic();
    assert_eq!(aptos_wrapper.trusted_state().version(), 22);

    assert_eq!(*aptos_wrapper.current_epoch(), 1);
    assert_eq!(*aptos_wrapper.major_version(), 100);
    assert_eq!(*aptos_wrapper.current_round(), 2);

    aptos_wrapper.commit_new_epoch();

    assert_eq!(*aptos_wrapper.major_version(), 200);
    assert_eq!(*aptos_wrapper.current_epoch(), 2);
    assert_eq!(*aptos_wrapper.current_round(), 1);
    assert_eq!(aptos_wrapper.trusted_state().version(), 24);

    aptos_wrapper.generate_traffic();
    assert_eq!(*aptos_wrapper.current_version(), 36)
}

#[test]
fn test_multiple_signers() {
    let mut aptos_wrapper = AptosWrapper::new(4, 15, 15);

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

    aptos_wrapper.generate_traffic();
    assert_eq!(aptos_wrapper.trusted_state().version(), 22);
}
