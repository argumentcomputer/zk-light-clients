// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

//! # Sync Committee module
//!
//! This module contains the data structures used by the Beacon Node to define the syc committee and
//! its related data.
//!
//! In the context of the Ethereum network, the sync committee is a subset of the full validator set
//! that is responsible for attesting to the latest block.
//!
//! For more information about the sync committee you can refer [to the Eth2 book](https://eth2book.info/capella/part2/building_blocks/committees/)
//! by Ben Edgington.

use crate::crypto::sig::{PublicKey, PUB_KEY_LEN};
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::extract_fixed_bytes;
use crate::types::{Bytes32, SYNC_COMMITTEE_SIZE};
use getset::Getters;

/// Current size of a merkle proof for a sync committee.
pub const SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS: usize = 5;

/// Merkle proof for a sync committee.
pub type SyncCommitteeBranch = [Bytes32; SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS];

/// Length of the serialized `SyncCommittee` in bytes.
pub const SYNC_COMMITTEE_BYTES_LEN: usize = SYNC_COMMITTEE_SIZE * PUB_KEY_LEN + PUB_KEY_LEN;

/// `SyncCommittee` is a committee of validators that are responsible for attesting to the latest
/// block. The sync committee is a subset of the full validator set.
///
/// From [the Altair upgrade specifications](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#synccommittee).
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct SyncCommittee {
    pubkeys: [PublicKey; SYNC_COMMITTEE_SIZE],
    aggregate_pubkey: PublicKey,
}

impl SyncCommittee {
    /// Serialize a `SyncCommittee` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `SyncCommittee` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Serialize each public key in the committee
        for pubkey in &self.pubkeys {
            bytes.extend(pubkey.to_ssz_bytes());
        }

        // Serialize the aggregate public key
        bytes.extend(self.aggregate_pubkey.to_ssz_bytes());

        bytes
    }

    /// Deserialize a `SyncCommittee` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `SyncCommittee` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `SyncCommittee` data structure or a `TypesError`.
    ///
    /// # Errors
    ///
    /// Returns a `TypesError` if the received bytes are not of the correct length or if the deserialization
    /// of internal types result in an error.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let expected_len = PUB_KEY_LEN * SYNC_COMMITTEE_SIZE + PUB_KEY_LEN;
        if bytes.len() != expected_len {
            return Err(TypesError::InvalidLength {
                expected: expected_len,
                actual: bytes.len(),
                structure: "SyncCommittee".into(),
            });
        }

        let pubkeys: [PublicKey; SYNC_COMMITTEE_SIZE] = (0..SYNC_COMMITTEE_SIZE)
            .map(|i| {
                let start = i * PUB_KEY_LEN;
                let end = start + PUB_KEY_LEN;
                PublicKey::from_ssz_bytes(&bytes[start..end])
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| {
                serde_error!(
                    "SyncCommittee",
                    "Could not convert the public keys to a slice of 512 elements"
                )
            })?;

        let cursor = PUB_KEY_LEN * SYNC_COMMITTEE_SIZE;

        let (cursor, aggregate_pubkey) =
            extract_fixed_bytes::<PUB_KEY_LEN>("SyncCommittee", bytes, cursor)?;

        if cursor != bytes.len() {
            return Err(TypesError::InvalidLength {
                expected: expected_len,
                actual: cursor,
                structure: "SyncCommittee".into(),
            });
        }

        Ok(Self {
            pubkeys,
            aggregate_pubkey: PublicKey::from_ssz_bytes(&aggregate_pubkey)?,
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
            .join("../test-assets/SyncCommitteeDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let execution_block_header = SyncCommittee::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = execution_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
