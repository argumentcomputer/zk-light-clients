// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Inclusion Prover module
//!
//! This module provides the prover implementation for the storage inclusion proof. The prover
//! is responsible for generating, executing, proving, and verifying proofs for the light client.

use crate::proofs::error::ProverError;
use crate::proofs::{ProofType, Prover, ProvingMode};
use crate::types::storage::GetProofResponse;
use anyhow::Result;
use ethereum_lc_core::crypto::hash::{HashValue, HASH_LENGTH};
use ethereum_lc_core::deserialization_error;
use ethereum_lc_core::merkle::storage_proofs::EIP1186Proof;
use ethereum_lc_core::types::bootstrap::Bootstrap;
use ethereum_lc_core::types::error::TypesError;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::{FinalityUpdate, Update};
use ethereum_lc_core::types::utils::{extract_u32, OFFSET_BYTE_LENGTH};
use ethereum_lc_core::types::{Address, ADDRESS_BYTES_LEN};
use ethereum_programs::INCLUSION_PROGRAM;
use sphinx_sdk::{ProverClient, SphinxProvingKey, SphinxStdin, SphinxVerifyingKey};
use std::fs;
use std::path::PathBuf;

/// The prover for the storage inclusion proof.
pub struct StorageInclusionProver {
    client: ProverClient,
    keys: (SphinxProvingKey, SphinxVerifyingKey),
}

impl Default for StorageInclusionProver {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageInclusionProver {
    /// Create a new `StorageInclusionProver`.
    ///
    /// # Returns
    ///
    /// A new `StorageInclusionProver`.
    pub fn new() -> Self {
        let client = ProverClient::new();
        let keys = client.setup(INCLUSION_PROGRAM);

        Self { client, keys }
    }

    /// Gets a `SphinxVerifyingKey`.
    ///
    /// # Returns
    ///
    /// A `SphinxVerifyingKey` that can be used for verifying the inclusion proof.
    pub fn get_vk(&self) -> SphinxVerifyingKey {
        self.keys.1.clone()
    }
}

/// The input for the storage inclusion proof.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageInclusionIn {
    store: LightClientStore,
    update: Update,
    eip1186_proof: EIP1186Proof,
}

impl StorageInclusionIn {
    /// Create a new `StorageInclusionIn`.
    ///
    /// # Arguments
    ///
    /// * `store` - The `LightClientStore` that wil be passed to the program.
    /// * `update` - The `Update` that will be passed to the program.
    /// * `eip1186_proof` - The `EIP1186Proof` that will be passed to the program.
    ///
    /// # Returns
    ///
    /// A new `StorageInclusionIn`.
    pub const fn new(store: LightClientStore, update: Update, eip1186_proof: EIP1186Proof) -> Self {
        Self {
            store,
            update,
            eip1186_proof,
        }
    }

    /// Serialize the `StorageInclusionIn` struct to SSZ bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `StorageInclusionIn` struct.
    pub fn to_ssz_bytes(&self) -> Result<Vec<u8>, TypesError> {
        let mut bytes = vec![];

        let store_offset: u32 = (OFFSET_BYTE_LENGTH * 3) as u32;
        let store_bytes = self.store.to_ssz_bytes()?;
        bytes.extend_from_slice(&store_offset.to_le_bytes());

        let update_offset = store_offset + store_bytes.len() as u32;
        let update_bytes = self.update.to_ssz_bytes()?;
        bytes.extend_from_slice(&update_offset.to_le_bytes());

        let eip1186_proof_offset = update_offset + update_bytes.len() as u32;
        let eip1186_proof_bytes = self.eip1186_proof.to_ssz_bytes();
        bytes.extend_from_slice(&eip1186_proof_offset.to_le_bytes());

        bytes.extend_from_slice(&store_bytes);
        bytes.extend_from_slice(&update_bytes);
        bytes.extend_from_slice(&eip1186_proof_bytes);

        Ok(bytes)
    }

    /// Deserialize a `StorageInclusionIn` struct from SSZ bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ encoded bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized `StorageInclusionIn` struct or a `TypesError`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let cursor = 0;
        let (cursor, store_offset) = extract_u32("CommmitteeChangeIn", bytes, cursor)?;
        let (cursor, update_offset) = extract_u32("CommmitteeChangeIn", bytes, cursor)?;
        let (cursor, eip1186_proof_offset) = extract_u32("CommmitteeChangeIn", bytes, cursor)?;

        // Deserialize the Light Client store
        if cursor != store_offset as usize {
            return Err(deserialization_error!(
                "CommmitteeChangeIn",
                "Invalid offset for store"
            ));
        }
        let store = LightClientStore::from_ssz_bytes(&bytes[cursor..update_offset as usize])?;

        // Deserialize the Update
        let update =
            Update::from_ssz_bytes(&bytes[update_offset as usize..eip1186_proof_offset as usize])?;

        // Deserialize the EIP1186Proof
        let eip1186_proof = EIP1186Proof::from_ssz_bytes(&bytes[eip1186_proof_offset as usize..])?;

        Ok(Self {
            store,
            update,
            eip1186_proof,
        })
    }
}

/// The output for the sync committee change proof.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StorageInclusionOut {
    finalized_block_height: u64,
    sync_committee_hash: HashValue,
    account_key: Address,
    account_value: HashValue,
    storage_key_value_len: u64,
    storage_key_value: Vec<StorageKeyValue>,
}

/// Represents the triplet of values output for storage values
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StorageKeyValue {
    key: Vec<u8>,
    value_len: u64,
    value: Vec<u8>,
}

impl Prover for StorageInclusionProver {
    const PROGRAM: &'static [u8] = INCLUSION_PROGRAM;
    type Error = ProverError;
    type StdIn = StorageInclusionIn;
    type StdOut = StorageInclusionOut;

    fn generate_sphinx_stdin(&self, inputs: Self::StdIn) -> Result<SphinxStdin, Self::Error> {
        let mut stdin = SphinxStdin::new();
        stdin.write(
            &inputs
                .store
                .to_ssz_bytes()
                .map_err(|err| ProverError::SphinxInput { source: err.into() })?,
        );
        stdin.write(
            &inputs
                .update
                .to_ssz_bytes()
                .map_err(|err| ProverError::SphinxInput { source: err.into() })?,
        );
        stdin.write(&inputs.eip1186_proof.to_ssz_bytes());
        Ok(stdin)
    }

    fn execute(&self, inputs: Self::StdIn) -> Result<Self::StdOut, Self::Error> {
        sphinx_sdk::utils::setup_logger();

        let stdin = self.generate_sphinx_stdin(inputs.clone())?;

        let (mut public_values, _) = self
            .client
            .execute(Self::PROGRAM, &stdin)
            .map_err(|err| ProverError::Execution { source: err.into() })?;

        let finalized_block_height = public_values.read::<u64>();
        let sync_committee_hash = HashValue::new(public_values.read::<[u8; HASH_LENGTH]>());
        let account_key = public_values.read::<[u8; ADDRESS_BYTES_LEN]>();
        let account_value = HashValue::new(public_values.read::<[u8; HASH_LENGTH]>());

        let storage_key_value_len = public_values.read::<u64>();

        let mut storage_key_value = vec![];

        for _ in 0..storage_key_value_len {
            let key = public_values.read::<Vec<u8>>();
            let value_len = public_values.read::<u64>();
            let value = public_values.read::<Vec<u8>>();
            storage_key_value.push(StorageKeyValue {
                key,
                value_len,
                value,
            });
        }

        Ok(StorageInclusionOut {
            sync_committee_hash,
            finalized_block_height,
            account_key,
            account_value,
            storage_key_value_len,
            storage_key_value,
        })
    }

    fn prove(&self, inputs: Self::StdIn, mode: ProvingMode) -> Result<ProofType, Self::Error> {
        let stdin = self.generate_sphinx_stdin(inputs)?;

        match mode {
            ProvingMode::STARK => self
                .client
                .prove(&self.keys.0, stdin)
                .map_err(|err| ProverError::Proving {
                    proof_type: mode.into(),
                    source: err.into(),
                })
                .map(ProofType::STARK),
            ProvingMode::SNARK => self
                .client
                .prove_plonk(&self.keys.0, stdin)
                .map_err(|err| ProverError::Proving {
                    proof_type: mode.into(),
                    source: err.into(),
                })
                .map(ProofType::SNARK),
        }
    }

    fn verify(&self, proof: &ProofType) -> Result<(), Self::Error> {
        let vk = &self.keys.1;

        match proof {
            ProofType::STARK(proof) => self
                .client
                .verify(proof, vk)
                .map_err(|err| ProverError::Verification { source: err.into() }),
            ProofType::SNARK(proof) => self
                .client
                .verify_plonk(proof, vk)
                .map_err(|err| ProverError::Verification { source: err.into() }),
        }
    }
}

struct TestAssets {
    store: LightClientStore,
    finality_update: FinalityUpdate,
    eip1186_proof: EIP1186Proof,
}

fn generate_test_assets() -> TestAssets {
    // Instantiate bootstrap data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/LightClientBootstrapDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate Update data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/LightClientUpdateDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let update = Update::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate finality update data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/LightClientFinalityUpdateDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let finality_update = FinalityUpdate::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate EIP1186 proof data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/base-data/EthGetProof.json");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let ethers_eip1186_proof: GetProofResponse = serde_json::from_slice(&test_bytes).unwrap();

    // Initialize the LightClientStore
    let checkpoint = "0xf783c545d2dd90cee6c4cb92a9324323ef397f6ec85e1a3d61c48cf6cfc979e2";
    let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

    store.process_light_client_update(&update).unwrap();

    TestAssets {
        store,
        finality_update,
        eip1186_proof: EIP1186Proof::try_from(ethers_eip1186_proof.result().clone()).unwrap(),
    }
}

/// Exports 'StorageInclusionIn' instance used as input for 'StorageInclusionProver'
pub fn generate_inclusion_proving_input_for_external_usage() -> StorageInclusionIn {
    let test_assets = generate_test_assets();
    StorageInclusionIn {
        store: test_assets.store.clone(),
        update: Update::from(test_assets.finality_update.clone()),
        eip1186_proof: test_assets.eip1186_proof.clone(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ethereum_lc_core::crypto::hash::keccak256_hash;

    #[test]
    fn test_execute_inclusion() {
        let test_assets = generate_test_assets();

        let prover = StorageInclusionProver::new();

        let inclusion_input = StorageInclusionIn {
            store: test_assets.store.clone(),
            update: Update::from(test_assets.finality_update.clone()),
            eip1186_proof: test_assets.eip1186_proof.clone(),
        };

        let inclusion_output = prover.execute(inclusion_input).unwrap();

        assert_eq!(
            inclusion_output.sync_committee_hash,
            keccak256_hash(&test_assets.store.current_sync_committee().to_ssz_bytes()).unwrap()
        );
        assert_eq!(
            &inclusion_output.finalized_block_height,
            test_assets
                .finality_update
                .finalized_header()
                .beacon()
                .slot()
        );
        assert_eq!(
            inclusion_output.account_value,
            keccak256_hash(&test_assets.eip1186_proof.address)
                .expect("could not hash account address")
        );
        assert_eq!(
            inclusion_output.storage_key_value_len,
            test_assets.eip1186_proof.storage_proof.len() as u64
        );

        for i in 0..inclusion_output.storage_key_value_len as usize {
            assert_eq!(
                inclusion_output.storage_key_value[i].key,
                test_assets.eip1186_proof.storage_proof[i].key.clone()
            );
            assert_eq!(
                inclusion_output.storage_key_value[i].value_len,
                test_assets.eip1186_proof.storage_proof[i].value.len() as u64
            );
            assert_eq!(
                inclusion_output.storage_key_value[i].value,
                test_assets.eip1186_proof.storage_proof[i].value.clone()
            );
        }
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_stark_storage_inclusion() {
        use std::time::Instant;

        let test_assets = generate_test_assets();

        let prover = StorageInclusionProver::new();

        let inclusion_inputs = StorageInclusionIn {
            store: test_assets.store.clone(),
            update: Update::from(test_assets.finality_update.clone()),
            eip1186_proof: test_assets.eip1186_proof.clone(),
        };

        println!("Starting STARK proving for sync committee change...");
        let start = Instant::now();

        let _ = prover.prove(inclusion_inputs, ProvingMode::STARK).unwrap();
        println!("Proving took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_snark_storage_inclusion() {
        use std::time::Instant;

        let test_assets = generate_test_assets();

        let prover = StorageInclusionProver::new();

        let inclusion_inputs = StorageInclusionIn {
            store: test_assets.store.clone(),
            update: Update::from(test_assets.finality_update.clone()),
            eip1186_proof: test_assets.eip1186_proof.clone(),
        };

        println!("Starting SNARK proving for sync committee change...");
        let start = Instant::now();

        let _ = prover.prove(inclusion_inputs, ProvingMode::SNARK).unwrap();
        println!("Proving took {:?}", start.elapsed());
    }
}
