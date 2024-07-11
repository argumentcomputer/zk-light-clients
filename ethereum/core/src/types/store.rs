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
use crate::merkle::proof::{
    is_current_committee_proof_valid, is_finality_proof_valid, is_next_committee_proof_valid,
};
use crate::merkle::Merkleized;
use crate::types::block::LightClientHeader;
use crate::types::bootstrap::Bootstrap;
use crate::types::committee::SyncCommittee;
use crate::types::error::{ConsensusError, StoreError};
use crate::types::signing_data::SigningData;
use crate::types::update::Update;
use crate::types::utils::{calc_sync_period, DOMAIN_BEACON_DENEB};
use crate::types::Bytes32;
use anyhow::Result;
use getset::Getters;

/// The `LightClientStore` represents the fill state for our Light Client. It includes the necessary
/// data to be maintained to verify the consensus rules in future updates.
#[derive(Debug, Clone, Getters)]
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
        if &trusted_block_root != bootstrap_block_root.as_ref() {
            return Err(StoreError::InvalidBootstrap {
                expected: format!("0x{}", hex::encode(trusted_block_root)),
                actual: format!("0x{}", hex::encode(bootstrap_block_root.as_ref())),
            });
        }

        // Confirm that the given sync committee was committed in the block
        let is_valid = is_current_committee_proof_valid(
            bootstrap.header(),
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
    fn validate_light_client_update(&self, update: &Update) -> Result<(), ConsensusError> {
        // Ensure we at least have 1 signer
        if update
            .sync_aggregate()
            .sync_committee_bits()
            .iter()
            .sum::<u8>()
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
            update.attested_header(),
            &mut update.finalized_header().beacon().clone(),
            update.finality_branch(),
        )
        .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        if !is_valid {
            return Err(ConsensusError::InvalidFinalityProof);
        }

        // Ensure that the next sync committee proof is valid
        let is_valid = is_next_committee_proof_valid(
            update.attested_header(),
            &mut update.next_sync_committee().clone(),
            update.next_sync_committee_branch(),
        )
        .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        if !is_valid {
            return Err(ConsensusError::InvalidNextSyncCommitteeProof);
        }

        // Verify signature on the received data
        let sync_committee = if update_sig_period == store_period {
            self.current_sync_committee()
        } else {
            &self.next_sync_committee().clone().unwrap()
        };

        let pks =
            sync_committee.get_participant_pubkeys(update.sync_aggregate().sync_committee_bits());

        let header_root = update
            .attested_header()
            .beacon()
            .hash_tree_root()
            .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        let signing_data = SigningData::new(*header_root.as_ref(), DOMAIN_BEACON_DENEB);

        let signing_root = signing_data
            .hash_tree_root()
            .map_err(|err| ConsensusError::MerkleError { source: err.into() })?;

        let aggregated_pubkey = PublicKey::aggregate(&pks)
            .map_err(|err| ConsensusError::SignatureError { source: err.into() })?;

        update
            .sync_aggregate()
            .sync_committee_signature()
            .verify(signing_root.hash(), &aggregated_pubkey)
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
}

#[cfg(test)]
mod test {
    use crate::merkle::Merkleized;
    use crate::types::bootstrap::Bootstrap;
    use crate::types::store::LightClientStore;
    use crate::types::update::Update;
    use std::env::current_dir;
    use std::fs;

    #[test]
    fn test_simple_validate_and_apply_update() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientBootstrapDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        let checkpoint = "0xefb4338d596b9d335b2da176dc85ee97469fc80c7e2d35b9b9c1558b4602077a";
        let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

        store.validate_light_client_update(&update).unwrap();

        // Apply the update, this should only update the next_sync_committee value
        store.apply_light_client_update(&update);

        assert_eq!(
            store
                .next_sync_committee()
                .clone()
                .unwrap()
                .hash_tree_root()
                .unwrap(),
            update.next_sync_committee().hash_tree_root().unwrap()
        )
    }

    #[test]
    fn test_process_update() {
        // Instantiate bootstrap data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientBootstrapDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate Update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        // Instantiate new period Update data
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientUpdateNewPeriodDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update_new_period = Update::from_ssz_bytes(&test_bytes).unwrap();

        // Initialize the LightClientStore
        let checkpoint = "0xefb4338d596b9d335b2da176dc85ee97469fc80c7e2d35b9b9c1558b4602077a";
        let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

        // Note: The data is not passed through process_light_client_update as the update is never applied because quorum is not met on the static data

        // Validate base update for next sync committee
        store.process_light_client_update(&update).unwrap();

        let tmp_next_sync_committee = store.next_sync_committee().clone().unwrap();

        // Validate base update for new period
        store
            .process_light_client_update(&update_new_period)
            .unwrap();

        // Current sync committee should have taken the value of the next sync committee
        assert_eq!(
            store.current_sync_committee().hash_tree_root().unwrap(),
            tmp_next_sync_committee.hash_tree_root().unwrap()
        );
        // Next sync committee should have taken the value of the update
        assert_eq!(
            store
                .next_sync_committee()
                .clone()
                .unwrap()
                .hash_tree_root()
                .unwrap(),
            update_new_period
                .next_sync_committee()
                .hash_tree_root()
                .unwrap()
        );
        // Finalized header should have taken the value of the update finalized header
        assert_eq!(
            store.finalized_header().hash_tree_root().unwrap(),
            update_new_period
                .finalized_header()
                .hash_tree_root()
                .unwrap()
        );
        // Optimistic header should have taken the value of the update attested header
        assert_eq!(
            store.optimistic_header().hash_tree_root().unwrap(),
            update_new_period
                .attested_header()
                .hash_tree_root()
                .unwrap()
        )
    }
}
