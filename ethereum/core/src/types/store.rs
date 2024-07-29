// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Light Client Store
//!
//! The `LightClientStore` represents the fill state for our Light Client. It includes the necessary
//! data to be maintained to verify the consensus rules in future updates. This data structure lives
//! as long as the Light Client is running.
//!
//! It notably exposes the main entry point for consensus verification through the `process_light_client_update`
//! function. This function will process the given `Update` data and apply it to the `LightClientStore` if it is valid.

use crate::crypto::sig::PublicKey;
use crate::merkle::update_proofs::{
    is_current_committee_proof_valid, is_finality_proof_valid, is_next_committee_proof_valid,
};
use crate::merkle::Merkleized;
use crate::types::block::{LightClientHeader, LIGHT_CLIENT_HEADER_BASE_BYTES_LEN};
use crate::types::bootstrap::Bootstrap;
use crate::types::committee::{SyncCommittee, SyncCommitteeBranch, SYNC_COMMITTEE_BYTES_LEN};
use crate::types::error::{ConsensusError, StoreError, TypesError};
use crate::types::signing_data::SigningData;
use crate::types::update::{CompactUpdate, Update};
use crate::types::utils::{
    calc_sync_period, extract_u32, extract_u64, DOMAIN_BEACON_DENEB, OFFSET_BYTE_LENGTH, U64_LEN,
};
use crate::types::Bytes32;
use crate::{deserialization_error, serialization_error};
use anyhow::Result;
use getset::Getters;

pub const LIGHT_CLIENT_STORE_BASE_LENGTH: usize =
    LIGHT_CLIENT_HEADER_BASE_BYTES_LEN * 2 + SYNC_COMMITTEE_BYTES_LEN + U64_LEN * 2 + 1;

pub const FINALIZED_HEADER_OFFSET: usize = OFFSET_BYTE_LENGTH
    + SYNC_COMMITTEE_BYTES_LEN
    + OFFSET_BYTE_LENGTH
    + OFFSET_BYTE_LENGTH
    + U64_LEN * 2;

/// The `LightClientStore` represents the fill state for our Light Client. It includes the necessary
/// data to be maintained to verify the consensus rules in future updates.
#[derive(Debug, Clone, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct LightClientStore {
    finalized_header: LightClientHeader,
    current_sync_committee: SyncCommittee,
    next_sync_committee: Option<SyncCommittee>,
    optimistic_header: LightClientHeader,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
}

impl LightClientStore {
    /// Consumes the `LightClientStore` and returns the `current_sync_committee`.
    ///
    /// This method moves the `current_sync_committee` field out
    /// of the `LightClientStore` struct, consuming the struct in the process.
    /// As a result, the `LightClientStore` cannot be used after this method is called.
    ///
    /// # Returns
    ///
    /// The current sync committee.
    pub fn into_current_sync_committee(self) -> SyncCommittee {
        self.current_sync_committee
    }

    /// Consumes the `LightClientStore` and returns the `next_sync_committee`,
    /// if it exists.
    ///
    /// This method moves the `next_sync_committee` field out of the
    /// `LightClientStore` struct, consuming the struct in the process.
    /// As a result, the `LightClientStore` cannot be used after this
    /// method is called.
    ///
    /// # Returns
    ///
    /// - `Option<SyncCommittee>`: An `Option` containing the next synchronization committee if it exists, or `None` if it does not.
    pub fn into_next_sync_committee(self) -> Option<SyncCommittee> {
        self.next_sync_committee
    }

    /// Initializes the `LightClientStore` with the given `Bootstrap` data.
    ///
    /// # Arguments
    ///
    /// * `trusted_block_root` - The block root of the trusted checkpoint.
    /// * `bootstrap` - The `Bootstrap` data to initialize the store.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized `LightClientStore` or a `StoreError` if the given
    pub fn initialize(
        trusted_block_root: Bytes32,
        bootstrap: &Bootstrap,
    ) -> Result<Self, StoreError> {
        // Ensure that we receive the `Bootstrap` for the correct checkpoint
        let bootstrap_block_root = bootstrap
            .header()
            .beacon()
            .hash_tree_root()
            .map_err(|err| StoreError::MerkleError { source: err.into() })?;
        if trusted_block_root != bootstrap_block_root.hash() {
            return Err(StoreError::InvalidBootstrap {
                expected: format!("0x{}", hex::encode(trusted_block_root)),
                actual: format!("0x{}", hex::encode(bootstrap_block_root.as_ref())),
            });
        }

        // Confirm that the given sync committee was committed in the block
        let is_valid = is_current_committee_proof_valid(
            bootstrap.header().beacon().state_root(),
            &mut bootstrap.current_sync_committee().clone(),
            bootstrap.current_sync_committee_branch(),
        )
        .map_err(|err| StoreError::InvalidCurrentCommitteeProof { source: err.into() })?;

        if !is_valid {
            return Err(StoreError::InvalidCurrentCommitteeProof {
                source: "Invalid proof sent in Bootstrap".into(),
            });
        }

        Ok(Self {
            finalized_header: bootstrap.header().clone(),
            current_sync_committee: bootstrap.current_sync_committee().clone(),
            next_sync_committee: None,
            optimistic_header: bootstrap.header().clone(),
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
        })
    }

    /// Main entrypoint for validating a sync committee change. This function will process the given
    /// `Update` data and apply it to the `LightClientStore` if it is valid.
    ///
    /// # Arguments
    ///
    /// * `update` - The `Update` data to process.
    ///
    /// # Returns
    ///
    /// A `Result` containing `()` if the update was processed successfully, or a `ConsensusError` if
    /// the update is invalid.
    ///
    /// # Notes
    ///
    /// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/5cce790decfb362bef300a4ca9f8075b1699ccb1/specs/altair/light-client/sync-protocol.md#process_light_client_update).
    pub fn process_light_client_update(&mut self, update: &Update) -> Result<(), ConsensusError> {
        // Validate the update
        self.validate_light_client_update(update)?;

        let number_signers = update
            .sync_aggregate()
            .sync_committee_bits()
            .iter()
            .map(|&bit| u64::from(bit))
            .sum::<u64>();

        // Update current maximum active participants
        self.current_max_active_participants =
            std::cmp::max(self.current_max_active_participants, number_signers);

        // Update optimistic header if
        // - we have more signatures than what we have stored for previous periods
        // - it is newer than the one we previously stored
        if number_signers > self.get_safety_threshold()
            && (update.attested_header().beacon().slot() > self.optimistic_header().beacon().slot())
        {
            self.optimistic_header = update.attested_header().clone();
        }

        let update_has_finalized_next_sync_committee = self.next_sync_committee().is_none()
            && calc_sync_period(update.attested_header().beacon().slot())
                == calc_sync_period(update.finalized_header().beacon().slot());

        // Apply update if:
        // - enough signatures
        // - newer block compated to the one stored OR if we get to initialize the next sync committee
        if number_signers * 3 >= update.sync_aggregate().sync_committee_bits().len() as u64 * 2
            && (update.finalized_header().beacon().slot() > self.finalized_header().beacon().slot()
                || update_has_finalized_next_sync_committee)
        {
            self.apply_light_client_update(update)
        }

        Ok(())
    }

    /// This function will validate the received `Update` data against the current state of the
    /// `LightClientStore`.
    ///
    /// # Arguments
    ///
    /// * `update` - The `Update` data to validate.
    ///
    /// # Returns
    ///
    /// A `Result` containing `()` if the update is valid, or a `ConsensusError` if the update is
    /// invalid.
    ///
    /// # Notes
    ///
    /// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/5cce790decfb362bef300a4ca9f8075b1699ccb1/specs/altair/light-client/sync-protocol.md#validate_light_client_update).
    pub fn validate_light_client_update(&self, update: &Update) -> Result<(), ConsensusError> {
        // Ensure we at least have 1 signer
        if update
            .sync_aggregate()
            .sync_committee_bits()
            .iter()
            .map(|&bit| u64::from(bit))
            .sum::<u64>()
            < 1
        {
            return Err(ConsensusError::InsufficientSigners);
        }

        // Assert that the received data make sense chronologically
        let valid_time = update.signature_slot() > update.attested_header().beacon().slot()
            && update.attested_header().beacon().slot()
                >= update.finalized_header().beacon().slot();

        if !valid_time {
            return Err(ConsensusError::InvalidTimestamp);
        }

        // We either want to receive:
        // - at initialization, an update for the same period that contains the next_sync_committee
        // - during the light client lifetime, an update for a new period
        let snapshot_period = calc_sync_period(self.finalized_header().beacon().slot());
        let update_sig_period = calc_sync_period(update.signature_slot());
        let valid_period = if self.next_sync_committee().is_some() {
            update_sig_period == snapshot_period || update_sig_period == snapshot_period + 1
        } else {
            update_sig_period == snapshot_period
        };

        if !valid_period {
            return Err(ConsensusError::InvalidPeriod);
        }

        // If the update we receive slot is less than or equal to the latest verified finalized slot,
        // it is not relevant. The only exception is at initialization when we still don't know the
        // next_sync_committee
        let update_attested_period = calc_sync_period(update.attested_header().beacon().slot());
        let store_period = calc_sync_period(self.finalized_header().beacon().slot());

        let update_has_next_committee =
            self.next_sync_committee().is_none() && update_attested_period == store_period;

        if update.attested_header().beacon().slot() <= self.finalized_header().beacon().slot()
            && !update_has_next_committee
        {
            return Err(ConsensusError::NotRelevant);
        }

        // Ensure that the received finality proof is valid
        let is_valid = is_finality_proof_valid(
            update.attested_header().beacon().state_root(),
            &mut update.finalized_header().beacon().clone(),
            update.finality_branch(),
        )
        .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        if !is_valid {
            return Err(ConsensusError::InvalidFinalityProof);
        }

        // Ensure that the next sync committee proof is valid
        if update.next_sync_committee_branch() == &SyncCommitteeBranch::default() {
            if update.next_sync_committee() != &SyncCommittee::default() {
                return Err(ConsensusError::ExpectedFinalityUpdate);
            }
        } else {
            let is_valid = is_next_committee_proof_valid(
                update.attested_header().beacon().state_root(),
                &mut update.next_sync_committee().clone(),
                update.next_sync_committee_branch(),
            )
            .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

            if !is_valid {
                return Err(ConsensusError::InvalidNextSyncCommitteeProof);
            }
        }

        // Verify signature on the received data
        let sync_committee = if update_sig_period == store_period {
            self.current_sync_committee().clone()
        } else {
            self.next_sync_committee().clone().unwrap()
        };

        let pks =
            sync_committee.get_participant_pubkeys(update.sync_aggregate().sync_committee_bits());

        let header_root = update
            .attested_header()
            .beacon()
            .hash_tree_root()
            .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        let signing_data = SigningData::new(header_root.hash(), DOMAIN_BEACON_DENEB);

        let signing_root = signing_data
            .hash_tree_root()
            .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        let aggregated_pubkey = PublicKey::aggregate(&pks)
            .map_err(|err| ConsensusError::SignatureError { source: err.into() })?;

        update
            .sync_aggregate()
            .sync_committee_signature()
            .verify(signing_root.as_ref(), &aggregated_pubkey)
            .map_err(|err| ConsensusError::SignatureError { source: err.into() })
    }

    /// Applies the given `Update` to the `LightClientStore`.
    ///
    /// # Arguments
    ///
    /// * `update` - The `Update` to apply.
    ///
    /// # Notes
    ///
    /// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/5cce790decfb362bef300a4ca9f8075b1699ccb1/specs/altair/light-client/sync-protocol.md#apply_light_client_update).
    fn apply_light_client_update(&mut self, update: &Update) {
        let snapshot_period = calc_sync_period(self.finalized_header().beacon().slot());
        let update_period = calc_sync_period(update.attested_header().beacon().slot());

        if self.next_sync_committee().is_none() {
            self.next_sync_committee = Some(update.next_sync_committee().clone());
        } else if update_period == snapshot_period + 1 {
            self.current_sync_committee = self.next_sync_committee().clone().unwrap();
            self.next_sync_committee = Some(update.next_sync_committee().clone());
            self.previous_max_active_participants = self.current_max_active_participants;
            self.current_max_active_participants = 0;
        }

        if update.finalized_header().beacon().slot() > self.finalized_header().beacon().slot() {
            self.finalized_header = update.finalized_header().clone();
            if self.finalized_header().beacon().slot() > self.optimistic_header().beacon().slot() {
                self.optimistic_header = self.finalized_header().clone();
            }
        }
    }

    /// Calculates the safety threshold based on the maximum number of active participants.
    ///
    /// # Returns
    ///
    /// The safety threshold.
    ///
    /// # Notes
    ///
    /// From [the Altaïr sepcifications](https://github.com/ethereum/consensus-specs/blob/5cce790decfb362bef300a4ca9f8075b1699ccb1/specs/altair/light-client/sync-protocol.md#get_safety_threshold).
    fn get_safety_threshold(&self) -> u64 {
        std::cmp::max(
            self.previous_max_active_participants,
            self.current_max_active_participants,
        ) / 2
    }

    pub fn to_ssz_bytes(&self) -> Result<Vec<u8>, TypesError> {
        let mut bytes = Vec::new();

        // Serialize the finalized header offset
        let finalized_header_bytes = self.finalized_header.to_ssz_bytes();
        bytes.extend_from_slice(&(FINALIZED_HEADER_OFFSET as u32).to_le_bytes());

        // Serialize the current sync committee
        let current_sync_committee_bytes = self.current_sync_committee.to_ssz_bytes();
        bytes.extend_from_slice(&current_sync_committee_bytes);

        // Serialize the next sync committee offset
        let next_sync_committee_offset = FINALIZED_HEADER_OFFSET + finalized_header_bytes.len();
        let next_sync_committee_bytes: Vec<u8> = if self.next_sync_committee.is_none() {
            vec![0]
        } else {
            let mut next_sync_committee_bytes = vec![1];
            next_sync_committee_bytes
                .extend_from_slice(&self.next_sync_committee.clone().unwrap().to_ssz_bytes());
            next_sync_committee_bytes
        };
        bytes.extend_from_slice(&(next_sync_committee_offset as u32).to_le_bytes());

        // Serialize optimistic header offset
        let optimistic_header_offset = next_sync_committee_offset + next_sync_committee_bytes.len();
        let optimistic_header_bytes = self.optimistic_header.to_ssz_bytes();
        bytes.extend_from_slice(&(optimistic_header_offset as u32).to_le_bytes());

        // Serialize previous max active participants
        bytes.extend_from_slice(&self.previous_max_active_participants.to_le_bytes());

        // Serialize current max active participants
        bytes.extend_from_slice(&self.current_max_active_participants.to_le_bytes());

        if bytes.len() != FINALIZED_HEADER_OFFSET {
            return Err(serialization_error!(
                "LightClientStore",
                "Invalid offset for finalized_header"
            ));
        }

        // Serialize the finalized header
        bytes.extend_from_slice(&finalized_header_bytes);

        if bytes.len() != next_sync_committee_offset {
            return Err(serialization_error!(
                "LightClientStore",
                "Invalid offset for next_sync_committee"
            ));
        }

        // Serialize the next sync committee
        bytes.extend_from_slice(&next_sync_committee_bytes);

        if bytes.len() != optimistic_header_offset {
            return Err(serialization_error!(
                "LightClientStore",
                "Invalid offset for optimistic_header"
            ));
        }

        // Serialize the optimistic header
        bytes.extend_from_slice(&optimistic_header_bytes);

        Ok(bytes)
    }
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < LIGHT_CLIENT_STORE_BASE_LENGTH {
            return Err(TypesError::UnderLength {
                minimum: LIGHT_CLIENT_STORE_BASE_LENGTH,
                actual: bytes.len(),
                structure: "LightClientStore".into(),
            });
        }

        // Deserialize the finalized header offset
        let cursor = 0;
        let (cursor, finalized_header_offset) = extract_u32("LightClientStore", bytes, cursor)?;

        // Deserialize current sync committee
        let current_sync_committee =
            SyncCommittee::from_ssz_bytes(&bytes[cursor..cursor + SYNC_COMMITTEE_BYTES_LEN])?;

        // Deserialize the next sync committee offset
        let cursor = cursor + SYNC_COMMITTEE_BYTES_LEN;
        let (cursor, next_sync_committee_offset) = extract_u32("LightClientStore", bytes, cursor)?;

        // Deserialize the optimistic header offset
        let (cursor, optimistic_header_offset) = extract_u32("LightClientStore", bytes, cursor)?;

        // Deserialize the previous max active participants
        let (cursor, previous_max_active_participants) =
            extract_u64("LightClientStore", bytes, cursor)?;

        // Deserialize the current max active participants
        let (cursor, current_max_active_participants) =
            extract_u64("LightClientStore", bytes, cursor)?;

        // Deserialize the finalized header
        if cursor != finalized_header_offset as usize {
            return Err(deserialization_error!(
                "LightClientStore",
                "Invalid offset for finalized_header"
            ));
        }

        let finalized_header =
            LightClientHeader::from_ssz_bytes(&bytes[cursor..next_sync_committee_offset as usize])?;

        // Deserialize the next sync committee
        let (cursor, next_sync_committee) = if bytes[next_sync_committee_offset as usize] == 0 {
            (next_sync_committee_offset as usize + 1, None)
        } else {
            (
                optimistic_header_offset as usize,
                Some(SyncCommittee::from_ssz_bytes(
                    &bytes[next_sync_committee_offset as usize + 1
                        ..optimistic_header_offset as usize],
                )?),
            )
        };

        // Deserialize the optimistic header
        if cursor != optimistic_header_offset as usize {
            return Err(deserialization_error!(
                "LightClientStore",
                "Invalid offset for optimistic_header"
            ));
        }

        let optimistic_header = LightClientHeader::from_ssz_bytes(&bytes[cursor..])?;

        Ok(Self {
            finalized_header,
            current_sync_committee,
            next_sync_committee,
            optimistic_header,
            previous_max_active_participants,
            current_max_active_participants,
        })
    }
}

/// Data structure used to represent a compact store. This is a reduced
/// version of the [`LightClientStore`] that is used to store the minimum
/// amount of data necessary to verify a [`CompactUpdate`].
#[derive(Debug, Clone, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct CompactStore {
    finalized_beacon_header_slot: u64,
    sync_committee: SyncCommittee,
}

impl CompactStore {
    /// Initializes the `CompactStore` with the given finalized beacon
    /// header slot and `SyncCommittee`.
    ///
    /// # Arguments
    ///
    /// * `finalized_beacon_header_slot` - The slot of the finalized beacon header.
    /// * `sync_committee` - The `SyncCommittee` to initialize the store.
    ///
    /// # Returns
    ///
    /// The initialized `CompactStore`.
    pub const fn new(finalized_beacon_header_slot: u64, sync_committee: SyncCommittee) -> Self {
        Self {
            finalized_beacon_header_slot,
            sync_committee,
        }
    }

    /// Serializes the `CompactStore` into SSZ bytes.
    ///
    /// # Returns
    ///
    /// The SSZ bytes of the `CompactStore`.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the snapshot period
        bytes.extend_from_slice(&self.finalized_beacon_header_slot.to_le_bytes());
        bytes.extend_from_slice(&self.sync_committee.to_ssz_bytes());

        bytes
    }

    /// Deserializes the `CompactStore` from SSZ bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ bytes to deserialize.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `CompactStore` or a `TypesError` if the bytes are
    /// invalid.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != U64_LEN + SYNC_COMMITTEE_BYTES_LEN {
            return Err(TypesError::UnderLength {
                minimum: U64_LEN + SYNC_COMMITTEE_BYTES_LEN,
                actual: bytes.len(),
                structure: "CompactStore".into(),
            });
        }

        // Deserialize the snapshot period
        let finalized_beacon_header_slot = u64::from_le_bytes(bytes[..U64_LEN].try_into().unwrap());

        // Deserialize the sync committee
        let sync_committee = SyncCommittee::from_ssz_bytes(&bytes[U64_LEN..])?;

        Ok(Self {
            finalized_beacon_header_slot,
            sync_committee,
        })
    }

    /// Validates the received `CompactUpdate` against the current
    /// state of the `CompactStore`.
    ///
    /// # Arguments
    ///
    /// * `update` - The `CompactUpdate` to validate.
    ///
    /// # Returns
    ///
    /// A `Result` containing `()` if the update is valid, or a `ConsensusError`
    /// if the update is invalid.
    pub fn validate_compact_update(&self, update: &CompactUpdate) -> Result<(), ConsensusError> {
        // Ensure we at least have 1 signer
        if update
            .sync_aggregate()
            .sync_committee_bits()
            .iter()
            .map(|&bit| u64::from(bit))
            .sum::<u64>()
            < 1
        {
            return Err(ConsensusError::InsufficientSigners);
        }

        // Assert that the received data make sense chronologically
        let valid_time = update.signature_slot() > update.attested_beacon_header().slot()
            && update.attested_beacon_header().slot() >= update.finalized_beacon_header().slot();

        if !valid_time {
            return Err(ConsensusError::InvalidTimestamp);
        }

        let snapshot_period = calc_sync_period(self.finalized_beacon_header_slot());
        let update_sig_period = calc_sync_period(update.signature_slot());
        if snapshot_period != update_sig_period {
            return Err(ConsensusError::InvalidPeriod);
        }

        // Ensure that the received finality proof is valid
        let is_valid = is_finality_proof_valid(
            update.attested_beacon_header().state_root(),
            &mut update.finalized_beacon_header().clone(),
            update.finality_branch(),
        )
        .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        if !is_valid {
            return Err(ConsensusError::InvalidFinalityProof);
        }

        let pks = self
            .sync_committee
            .get_participant_pubkeys(update.sync_aggregate().sync_committee_bits());

        let header_root = update
            .attested_beacon_header()
            .hash_tree_root()
            .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        let signing_data = SigningData::new(header_root.hash(), DOMAIN_BEACON_DENEB);

        let signing_root = signing_data
            .hash_tree_root()
            .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        let aggregated_pubkey = PublicKey::aggregate(&pks)
            .map_err(|err| ConsensusError::SignatureError { source: err.into() })?;

        update
            .sync_aggregate()
            .sync_committee_signature()
            .verify(signing_root.as_ref(), &aggregated_pubkey)
            .map_err(|err| ConsensusError::SignatureError { source: err.into() })
    }
}

#[cfg(test)]
mod test {
    use crate::merkle::Merkleized;
    use crate::types::bootstrap::Bootstrap;
    use crate::types::store::{CompactStore, LightClientStore};
    use crate::types::update::Update;
    use std::env::current_dir;
    use std::fs;

    struct TestAssets {
        store: LightClientStore,
        update: Update,
        update_new_period: Update,
    }

    fn generate_test_assets() -> TestAssets {
        // Instantiate bootstrap data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/LightClientBootstrapDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate Update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate new period Update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/LightClientUpdateNewPeriodDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update_new_period = Update::from_ssz_bytes(&test_bytes).unwrap();

        // Initialize the LightClientStore
        let checkpoint = "0xefb4338d596b9d335b2da176dc85ee97469fc80c7e2d35b9b9c1558b4602077a";
        let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        let store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

        TestAssets {
            store,
            update,
            update_new_period,
        }
    }

    #[test]
    fn test_simple_validate_and_apply_update() {
        let mut test_assets = generate_test_assets();

        test_assets
            .store
            .validate_light_client_update(&test_assets.update)
            .unwrap();

        // Apply the update, this should only update the next_sync_committee value
        test_assets
            .store
            .apply_light_client_update(&test_assets.update);

        assert_eq!(
            test_assets
                .store
                .next_sync_committee()
                .clone()
                .unwrap()
                .hash_tree_root()
                .unwrap(),
            test_assets
                .update
                .next_sync_committee()
                .hash_tree_root()
                .unwrap()
        )
    }

    #[test]
    fn test_process_update() {
        let mut test_assets = generate_test_assets();

        // Note: The data is not passed through process_light_client_update as the update is never applied because quorum is not met on the static data

        // Validate base update for next sync committee
        test_assets
            .store
            .process_light_client_update(&test_assets.update)
            .unwrap();

        let tmp_next_sync_committee = test_assets.store.next_sync_committee().clone().unwrap();

        // Validate base update for new period
        test_assets
            .store
            .process_light_client_update(&test_assets.update_new_period)
            .unwrap();

        // Current sync committee should have taken the value of the next sync committee
        assert_eq!(
            test_assets
                .store
                .current_sync_committee()
                .hash_tree_root()
                .unwrap(),
            tmp_next_sync_committee.hash_tree_root().unwrap()
        );
        // Next sync committee should have taken the value of the update
        assert_eq!(
            test_assets
                .store
                .next_sync_committee()
                .clone()
                .unwrap()
                .hash_tree_root()
                .unwrap(),
            test_assets
                .update_new_period
                .next_sync_committee()
                .hash_tree_root()
                .unwrap()
        );
        // Finalized header should have taken the value of the update finalized header
        assert_eq!(
            test_assets
                .store
                .finalized_header()
                .hash_tree_root()
                .unwrap(),
            test_assets
                .update_new_period
                .finalized_header()
                .hash_tree_root()
                .unwrap()
        );
        // Optimistic header should have taken the value of the update attested header
        assert_eq!(
            test_assets
                .store
                .optimistic_header()
                .hash_tree_root()
                .unwrap(),
            test_assets
                .update_new_period
                .attested_header()
                .hash_tree_root()
                .unwrap()
        )
    }

    #[test]
    fn test_ssz_serde_light_client_store() {
        let test_assets = generate_test_assets();

        let bytes = test_assets.store.to_ssz_bytes().unwrap();

        let deserialized_store = LightClientStore::from_ssz_bytes(&bytes);

        assert_eq!(test_assets.store, deserialized_store.unwrap());
    }

    #[test]
    fn test_ssz_serde_compact_store() {
        let test_assets = generate_test_assets();

        let compact_store = CompactStore::new(
            *test_assets.store.finalized_header().beacon().slot(),
            test_assets.store.current_sync_committee().clone(),
        );

        let serialized_store = compact_store.to_ssz_bytes();

        let deserialized_store = CompactStore::from_ssz_bytes(&serialized_store).unwrap();

        assert_eq!(compact_store, deserialized_store);
    }
}
