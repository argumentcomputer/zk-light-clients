// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use ethereum_lc_core::serde_error;
use ethereum_lc_core::types::block::{LightClientHeader, LIGHT_CLIENT_HEADER_BASE_BYTES_LEN};
use ethereum_lc_core::types::committee::{
    SyncCommittee, SyncCommitteeBranch, SYNC_COMMITTEE_BYTES_LEN, SYNC_COMMITTEE_PROOF_SIZE,
};
use ethereum_lc_core::types::error::TypesError;
use ethereum_lc_core::types::utils::OFFSET_BYTE_LENGTH;
use ethereum_lc_core::types::BYTES_32_LEN;
use getset::Getters;

/// `Bootstrap` represents the bootstrap data for the light client.
///
/// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/light-client/sync-protocol.md#lightclientbootstrap).
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct Bootstrap {
    header: LightClientHeader,
    current_sync_committee: SyncCommittee,
    current_sync_committee_branch: SyncCommitteeBranch,
}

impl Bootstrap {
    /// Serialize a `Bootstrap` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `Bootstrap` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Serialize header offset
        let offset = OFFSET_BYTE_LENGTH
            + SYNC_COMMITTEE_BYTES_LEN
            + SYNC_COMMITTEE_PROOF_SIZE * BYTES_32_LEN;
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());

        // Serialize the current sync committee
        bytes.extend(self.current_sync_committee.to_ssz_bytes());

        // Serialize the current sync committee branch
        for pubkey in &self.current_sync_committee_branch {
            bytes.extend(pubkey);
        }

        // Serialize the header
        bytes.extend(self.header.to_ssz_bytes());

        bytes
    }

    /// Deserialize a `Bootstrap` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `Bootstrap` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized `Bootstrap` data structure or a `TypesError`.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid SSZ representation of a `Bootstrap`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        // Define all bytes length & ensure that we receive the base expected number of bytes.
        let header_len = LIGHT_CLIENT_HEADER_BASE_BYTES_LEN;
        let sync_committee_len = SYNC_COMMITTEE_BYTES_LEN;
        let sync_committee_branch_len = SYNC_COMMITTEE_PROOF_SIZE * BYTES_32_LEN;

        if bytes.len() < header_len + sync_committee_len + sync_committee_branch_len {
            return Err(TypesError::UnderLength {
                minimum: header_len + sync_committee_len + sync_committee_branch_len,
                actual: bytes.len(),
                structure: "Bootstrap".into(),
            });
        }

        // Deserialize `LightClientHeader` offset
        let cursor = 0;
        let offset = u32::from_le_bytes(
            bytes[cursor..cursor + OFFSET_BYTE_LENGTH]
                .try_into()
                .map_err(|_| serde_error!("ExecutionBlockHeader", "Invalid offset bytes"))?,
        ) as usize;

        // Deserialize `SyncCommittee`.
        let cursor = cursor + OFFSET_BYTE_LENGTH;
        let current_sync_committee =
            SyncCommittee::from_ssz_bytes(&bytes[cursor..cursor + SYNC_COMMITTEE_BYTES_LEN])?;

        // Deserialize `SyncCommitteeBranch`
        let cursor = cursor + SYNC_COMMITTEE_BYTES_LEN;
        let current_sync_committee_branch = (0..SYNC_COMMITTEE_PROOF_SIZE)
            .map(|i| {
                let start = cursor + i * BYTES_32_LEN;
                let end = start + BYTES_32_LEN;
                let returned_bytes = &bytes[start..end];
                returned_bytes.try_into().map_err(|_| {
                    serde_error!(
                        "Bootstrap",
                        "Failed to convert bytes into SyncCommitteeBranch"
                    )
                })
            })
            .collect::<Result<Vec<[u8; BYTES_32_LEN]>, _>>()?
            .try_into()
            .map_err(|_| {
                serde_error!(
                    "Bootstrap",
                    "Failed to convert bytes into SyncCommitteeBranch"
                )
            })?;

        // Deserialize `LightClientHeader`
        let cursor = cursor + SYNC_COMMITTEE_PROOF_SIZE * BYTES_32_LEN;

        if cursor != offset {
            return Err(serde_error!("Bootstrap", "Invalid offset for header"));
        }

        let header = LightClientHeader::from_ssz_bytes(&bytes[cursor..])?;

        Ok(Self {
            header,
            current_sync_committee,
            current_sync_committee_branch,
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
            .join("../test-assets/LightClientBootstrapDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let execution_block_header = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = execution_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
