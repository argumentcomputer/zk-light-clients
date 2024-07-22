// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Light Client Update
//!
//! The module contains the `Update` data structure which is the payload that our Light Client leverages
//! to update its state to the latest one on the Beacon chain. The data structure notably contains
//! information about block header signature and sync committee changes.

use crate::crypto::sig::{SyncAggregate, SYNC_AGGREGATE_BYTES_LEN};
use crate::deserialization_error;
use crate::types::block::{LightClientHeader, LIGHT_CLIENT_HEADER_BASE_BYTES_LEN};
use crate::types::committee::{
    SyncCommittee, SyncCommitteeBranch, SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS,
    SYNC_COMMITTEE_BYTES_LEN,
};
use crate::types::error::TypesError;
use crate::types::utils::{extract_u32, extract_u64, OFFSET_BYTE_LENGTH, U64_LEN};
use crate::types::{FinalizedRootBranch, BYTES_32_LEN, FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS};
use getset::Getters;

/// Base length of a `Update` struct in bytes.
pub const UPDATE_BASE_BYTES_LEN: usize = LIGHT_CLIENT_HEADER_BASE_BYTES_LEN * 2
    + SYNC_COMMITTEE_BYTES_LEN
    + SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
    + FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
    + SYNC_AGGREGATE_BYTES_LEN
    + U64_LEN;

/// A data structure containing the necessary data for a light client to update its state from the Beacon chain.
///
/// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/81f3ea8322aff6b9fb15132d050f8f98b16bdba4/specs/altair/light-client/sync-protocol.md#lightclientupdate).
#[derive(Debug, Clone, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Update {
    attested_header: LightClientHeader,
    next_sync_committee: SyncCommittee,
    next_sync_committee_branch: SyncCommitteeBranch,
    finalized_header: LightClientHeader,
    finality_branch: FinalizedRootBranch,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl From<FinalityUpdate> for Update {
    fn from(finality_update: FinalityUpdate) -> Self {
        Self {
            attested_header: finality_update.attested_header,
            next_sync_committee: SyncCommittee::default(),
            next_sync_committee_branch: SyncCommitteeBranch::default(),
            finalized_header: finality_update.finalized_header,
            finality_branch: finality_update.finality_branch,
            sync_aggregate: finality_update.sync_aggregate,
            signature_slot: finality_update.signature_slot,
        }
    }
}

impl Update {
    /// Serialize the `Update` struct to SSZ bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `Update` struct.
    pub fn to_ssz_bytes(&self) -> Result<Vec<u8>, TypesError> {
        let mut bytes = vec![];

        // Serialize offset for the attested header
        let attested_header_offset = OFFSET_BYTE_LENGTH * 2
            + SYNC_COMMITTEE_BYTES_LEN
            + SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
            + FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
            + SYNC_AGGREGATE_BYTES_LEN
            + U64_LEN;
        bytes.extend_from_slice(&(attested_header_offset as u32).to_le_bytes());
        let attested_header_bytes = self.attested_header.to_ssz_bytes();

        // Serialize the next sync committee
        bytes.extend(self.next_sync_committee.to_ssz_bytes());

        // Serialize the next sync committee branch
        for pubkey in &self.next_sync_committee_branch {
            bytes.extend(pubkey);
        }

        // Serialize finalized header
        let finalized_header_offset = attested_header_bytes.len() + attested_header_offset;
        bytes.extend_from_slice(&(finalized_header_offset as u32).to_le_bytes());

        // Serialize the finality branch
        for root in &self.finality_branch {
            bytes.extend(root);
        }

        // Serialize the sync aggregate
        bytes.extend(self.sync_aggregate.to_ssz_bytes()?);

        // Serialize the signature slot
        bytes.extend_from_slice(&self.signature_slot.to_le_bytes());

        // Serialize the attested header
        bytes.extend(&attested_header_bytes);

        // Serialize the finalized header
        bytes.extend(self.finalized_header.to_ssz_bytes());

        Ok(bytes)
    }

    /// Deserialize a `Update` struct from SSZ bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ encoded bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `Update` struct or a `TypesError`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < UPDATE_BASE_BYTES_LEN {
            return Err(TypesError::UnderLength {
                minimum: UPDATE_BASE_BYTES_LEN,
                actual: bytes.len(),
                structure: "Update".into(),
            });
        }

        let cursor = 0;

        // Deserialize `LightClientHeader` offset
        let (cursor, offset_attested_header) = extract_u32("Update", bytes, cursor)?;

        // Deserialize `SyncCommittee`
        let current_sync_committee =
            SyncCommittee::from_ssz_bytes(&bytes[cursor..cursor + SYNC_COMMITTEE_BYTES_LEN])?;

        // Deserialize `SyncCommitteeBranch`
        let cursor = cursor + SYNC_COMMITTEE_BYTES_LEN;
        let current_sync_committee_branch = (0..SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS)
            .map(|i| {
                let start = cursor + i * BYTES_32_LEN;
                let end = start + BYTES_32_LEN;
                let returned_bytes = &bytes[start..end];
                returned_bytes.try_into().map_err(|_| {
                    deserialization_error!(
                        "Update",
                        "Failed to convert bytes into SyncCommitteeBranch"
                    )
                })
            })
            .collect::<Result<Vec<[u8; BYTES_32_LEN]>, _>>()?
            .try_into()
            .map_err(|_| {
                deserialization_error!("Update", "Failed to convert bytes into SyncCommitteeBranch")
            })?;

        // Deserialize `LightClientHeader` offset
        let cursor = cursor + SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS * BYTES_32_LEN;
        let (cursor, offset_finalized_header) = extract_u32("Update", bytes, cursor)?;

        // Deserialize `FinalizedRootBranch`
        let finality_branch = (0..FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS)
            .map(|i| {
                let start = cursor + i * BYTES_32_LEN;
                let end = start + BYTES_32_LEN;
                let returned_bytes = &bytes[start..end];
                returned_bytes.try_into().map_err(|_| {
                    deserialization_error!(
                        "Update",
                        "Failed to convert bytes into FinalizedRootBranch"
                    )
                })
            })
            .collect::<Result<Vec<[u8; BYTES_32_LEN]>, _>>()?
            .try_into()
            .map_err(|_| {
                deserialization_error!("Update", "Failed to convert bytes into FinalizedRootBranch")
            })?;

        // Deserialize `SyncAggregate`
        let cursor = cursor + FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS * BYTES_32_LEN;
        let sync_aggregate =
            SyncAggregate::from_ssz_bytes(&bytes[cursor..cursor + SYNC_AGGREGATE_BYTES_LEN])?;

        // Deserialize `u64`
        let cursor = cursor + SYNC_AGGREGATE_BYTES_LEN;
        let (cursor, signature_slot) = extract_u64("Update", bytes, cursor)?;

        // Deserialize attested `LightClientHeader`
        if cursor != offset_attested_header as usize {
            return Err(deserialization_error!(
                "Update",
                "Invalid offset for attested header"
            ));
        }
        let attested_header = LightClientHeader::from_ssz_bytes(
            &bytes[cursor
                ..cursor + offset_finalized_header as usize - offset_attested_header as usize],
        )?;

        // Deserialize finalized `LightClientHeader`
        let cursor = cursor + offset_finalized_header as usize - offset_attested_header as usize;
        if cursor != offset_finalized_header as usize {
            return Err(deserialization_error!(
                "Update",
                "Invalid offset for finalized header"
            ));
        }

        let finalized_header = LightClientHeader::from_ssz_bytes(&bytes[cursor..])?;

        Ok(Self {
            attested_header,
            next_sync_committee: current_sync_committee,
            next_sync_committee_branch: current_sync_committee_branch,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }
}

/// Base length of a `Update` struct in bytes.
pub const FINALITY_UPDATE_BASE_BYTES_LEN: usize = LIGHT_CLIENT_HEADER_BASE_BYTES_LEN * 2
    + FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
    + SYNC_AGGREGATE_BYTES_LEN
    + U64_LEN;

/// Structure representing a finality update that can be fetched from the Beacon network.
///
/// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate).
#[derive(Debug, Clone, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct FinalityUpdate {
    attested_header: LightClientHeader,
    finalized_header: LightClientHeader,
    finality_branch: FinalizedRootBranch,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
}

impl FinalityUpdate {
    /// Serialize the `FinalityUpdate` struct to SSZ bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `FinalityUpdate` struct.
    pub fn to_ssz_bytes(&self) -> Result<Vec<u8>, TypesError> {
        let mut bytes = vec![];

        // Serialize offset for the attested header
        let attested_header_offset = OFFSET_BYTE_LENGTH * 2
            + FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
            + SYNC_AGGREGATE_BYTES_LEN
            + U64_LEN;
        bytes.extend_from_slice(&(attested_header_offset as u32).to_le_bytes());
        let attested_header_bytes = self.attested_header.to_ssz_bytes();

        // Serialize finalized header
        let finalized_header_offset = attested_header_bytes.len() + attested_header_offset;
        bytes.extend_from_slice(&(finalized_header_offset as u32).to_le_bytes());

        // Serialize the finality branch
        for root in &self.finality_branch {
            bytes.extend(root);
        }

        // Serialize the sync aggregate
        bytes.extend(self.sync_aggregate.to_ssz_bytes()?);

        // Serialize the signature slot
        bytes.extend_from_slice(&self.signature_slot.to_le_bytes());

        // Serialize the attested header
        bytes.extend(&attested_header_bytes);

        // Serialize the finalized header
        bytes.extend(self.finalized_header.to_ssz_bytes());

        Ok(bytes)
    }

    /// Deserialize a `FinalityUpdate` struct from SSZ bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ encoded bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `FinalityUpdate` struct or a `TypesError`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < FINALITY_UPDATE_BASE_BYTES_LEN {
            return Err(TypesError::UnderLength {
                minimum: FINALITY_UPDATE_BASE_BYTES_LEN,
                actual: bytes.len(),
                structure: "Update".into(),
            });
        }

        let cursor = 0;

        // Deserialize `LightClientHeader` offset
        let (cursor, offset_attested_header) = extract_u32("Update", bytes, cursor)?;

        // Deserialize `LightClientHeader` offset
        let (cursor, offset_finalized_header) = extract_u32("Update", bytes, cursor)?;

        // Deserialize `FinalizedRootBranch`
        let finality_branch = (0..FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS)
            .map(|i| {
                let start = cursor + i * BYTES_32_LEN;
                let end = start + BYTES_32_LEN;
                let returned_bytes = &bytes[start..end];
                returned_bytes.try_into().map_err(|_| {
                    deserialization_error!(
                        "Update",
                        "Failed to convert bytes into FinalizedRootBranch"
                    )
                })
            })
            .collect::<Result<Vec<[u8; BYTES_32_LEN]>, _>>()?
            .try_into()
            .map_err(|_| {
                deserialization_error!("Update", "Failed to convert bytes into FinalizedRootBranch")
            })?;

        // Deserialize `SyncAggregate`
        let cursor = cursor + FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS * BYTES_32_LEN;
        let sync_aggregate =
            SyncAggregate::from_ssz_bytes(&bytes[cursor..cursor + SYNC_AGGREGATE_BYTES_LEN])?;

        // Deserialize `u64`
        let cursor = cursor + SYNC_AGGREGATE_BYTES_LEN;
        let (cursor, signature_slot) = extract_u64("Update", bytes, cursor)?;

        // Deserialize attested `LightClientHeader`
        if cursor != offset_attested_header as usize {
            return Err(deserialization_error!(
                "Update",
                "Invalid offset for attested header"
            ));
        }
        let attested_header = LightClientHeader::from_ssz_bytes(
            &bytes[cursor
                ..cursor + offset_finalized_header as usize - offset_attested_header as usize],
        )?;

        // Deserialize finalized `LightClientHeader`
        let cursor = cursor + offset_finalized_header as usize - offset_attested_header as usize;
        if cursor != offset_finalized_header as usize {
            return Err(deserialization_error!(
                "Update",
                "Invalid offset for finalized header"
            ));
        }

        let finalized_header = LightClientHeader::from_ssz_bytes(&bytes[cursor..])?;

        Ok(Self {
            attested_header,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::merkle::update_proofs::{is_finality_proof_valid, is_next_committee_proof_valid};
    use std::env::current_dir;
    use std::fs;

    #[test]
    fn test_ssz_serde_update() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = update.to_ssz_bytes().unwrap();

        assert_eq!(ssz_bytes, test_bytes);
    }

    #[test]
    fn test_update_proof() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        let valid = is_next_committee_proof_valid(
            update.attested_header(),
            &mut update.next_sync_committee().clone(),
            update.next_sync_committee_branch(),
        )
        .unwrap();

        assert!(valid);

        let valid = is_finality_proof_valid(
            update.attested_header(),
            &mut update.finalized_header().beacon().clone(),
            update.finality_branch(),
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_ssz_serde_finality_update() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let update = Update::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = update.to_ssz_bytes().unwrap();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
