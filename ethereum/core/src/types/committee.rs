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

use crate::crypto::sig::{PublicKey, Signature, PUB_KEY_LEN, SIG_LEN};
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::{extract_fixed_bytes, pack_bits, unpack_bits};
use crate::types::Bytes32;
use getset::Getters;

/// Constant number of validators in the sync committee.
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// Current size of a merkle proof for a sync committee.
///
/// From [the Lighthouse implementation](https://github.com/sigp/lighthouse/blob/v5.2.1/consensus/types/src/light_client_update.rs#L34)
/// and [the Altaïr specifications](https://github.com/ethereum/annotated-spec/blob/master/altair/sync-protocol.md#lightclientupdate).
pub const SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS: usize = 5;

/// Merkle proof for a sync committee.
pub type SyncCommitteeBranch = [Bytes32; SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS];

/// Length of the serialized `SyncCommittee` in bytes.
pub const SYNC_COMMITTEE_BYTES_LEN: usize = SYNC_COMMITTEE_SIZE * PUB_KEY_LEN + PUB_KEY_LEN;

/// Position in the merkle tree for the next sync committee.
pub const NEXT_SYNC_COMMITTEE_INDEX: usize = 55;

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

/// Size in SSZ serialized bytes for a [`SyncAggregate`].
pub const SYNC_AGGREGATE_BYTES_LEN: usize = SYNC_COMMITTEE_SIZE / 8 + SIG_LEN;

/// Structure that represents an aggregated signature on the Beacon chain. It contains the validator
/// index who signed the message as bits and the actual signature.
///
/// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/81f3ea8322aff6b9fb15132d050f8f98b16bdba4/specs/altair/beacon-chain.md#syncaggregate).
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct SyncAggregate {
    sync_committee_bits: [u8; SYNC_COMMITTEE_SIZE],
    sync_committee_signature: Signature,
}

impl SyncAggregate {
    /// Serialize a `SyncAggregate` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `SyncAggregate` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize sync_committee_bits as a packed bit array
        let packed_bits = pack_bits(&self.sync_committee_bits);
        bytes.extend_from_slice(&packed_bits);

        // Serialize sync_committee_signature
        bytes.extend_from_slice(&self.sync_committee_signature.to_ssz_bytes());

        bytes
    }

    /// Deserialize a `SyncAggregate` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `SyncAggregate` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized `SyncAggregate` data structure or a `TypesError`.
    ///
    /// # Errors
    ///
    /// Returns a `TypesError` if the bytes are not long enough to create a `SyncAggregate` or if the deserialization of internal types throws an error.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != SYNC_AGGREGATE_BYTES_LEN {
            return Err(TypesError::InvalidLength {
                structure: "SyncAggregate".into(),
                expected: SYNC_AGGREGATE_BYTES_LEN,
                actual: bytes.len(),
            });
        }

        // Deserialize sync_committee_bits as a bit array
        let sync_committee_bits =
            unpack_bits(&bytes[0..SYNC_COMMITTEE_SIZE / 8], SYNC_COMMITTEE_SIZE)
                .try_into()
                .map_err(|_| {
                    serde_error!("SyncAggregate", "Could not deserialize sync_committee_bits")
                })?;

        // Deserialize sync_committee_signature
        let sync_committee_signature: Signature = Signature::from_ssz_bytes(
            &bytes[SYNC_COMMITTEE_SIZE / 8..SYNC_COMMITTEE_SIZE / 8 + SIG_LEN],
        )?;

        Ok(Self {
            sync_committee_bits,
            sync_committee_signature,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env::current_dir;
    use std::fs;

    #[test]
    fn test_ssz_serde_sync_committee() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/SyncCommitteeDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let execution_block_header = SyncCommittee::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = execution_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }

    #[test]
    fn test_ssz_serde_sync_aggregate() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/SyncAggregateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let execution_block_header = SyncAggregate::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = execution_block_header.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
