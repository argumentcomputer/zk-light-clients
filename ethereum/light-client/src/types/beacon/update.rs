// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Light Client Update
//!
//! The module contains the `Update` data structure which is the payload that our Light Client leverages
//! to update its state to the latest one on the Beacon chain. The data structure notably contains
//! information about block header signature and sync committee changes.

use ethereum_lc_core::serde_error;
use ethereum_lc_core::types::block::{LightClientHeader, LIGHT_CLIENT_HEADER_BASE_BYTES_LEN};
use ethereum_lc_core::types::committee::{
    SyncAggregate, SyncCommittee, SyncCommitteeBranch, SYNC_AGGREGATE_BYTES_LEN,
    SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS, SYNC_COMMITTEE_BYTES_LEN,
};
use ethereum_lc_core::types::error::TypesError;
use ethereum_lc_core::types::utils::{extract_u32, extract_u64, OFFSET_BYTE_LENGTH};
use ethereum_lc_core::types::{
    FinalizedRootBranch, BYTES_32_LEN, FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS, U64_LEN,
};
use getset::Getters;

/// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/81f3ea8322aff6b9fb15132d050f8f98b16bdba4/specs/altair/light-client/sync-protocol.md#lightclientupdate).
#[derive(Debug, Clone, Getters)]
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

impl Update {
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

    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let expected_len = LIGHT_CLIENT_HEADER_BASE_BYTES_LEN * 2
            + SYNC_COMMITTEE_BYTES_LEN
            + SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
            + FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS * BYTES_32_LEN
            + SYNC_AGGREGATE_BYTES_LEN
            + U64_LEN;

        if bytes.len() < expected_len {
            return Err(TypesError::UnderLength {
                minimum: expected_len,
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
                    serde_error!("Update", "Failed to convert bytes into SyncCommitteeBranch")
                })
            })
            .collect::<Result<Vec<[u8; BYTES_32_LEN]>, _>>()?
            .try_into()
            .map_err(|_| {
                serde_error!("Update", "Failed to convert bytes into SyncCommitteeBranch")
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
                    serde_error!("Update", "Failed to convert bytes into FinalizedRootBranch")
                })
            })
            .collect::<Result<Vec<[u8; BYTES_32_LEN]>, _>>()?
            .try_into()
            .map_err(|_| {
                serde_error!("Update", "Failed to convert bytes into FinalizedRootBranch")
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
            return Err(serde_error!("Update", "Invalid offset for attested header"));
        }
        let attested_header = LightClientHeader::from_ssz_bytes(
            &bytes[cursor
                ..cursor + offset_finalized_header as usize - offset_attested_header as usize],
        )?;

        // Deserialize finalized `LightClientHeader`
        let cursor = cursor + offset_finalized_header as usize - offset_attested_header as usize;
        if cursor != offset_finalized_header as usize {
            return Err(serde_error!(
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

#[cfg(test)]
mod test {
    use super::*;
    use std::env::current_dir;
    use std::fs;

    #[test]
    fn test_ssz_serde() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/LightClientUpdateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let execution_block_header = Update::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = execution_block_header.to_ssz_bytes().unwrap();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
