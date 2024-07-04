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

use crate::crypto::error::CryptoError;
use crate::crypto::hash::{sha2_hash_concat, HashValue};
use crate::crypto::sig::{PublicKey, PUB_KEY_LEN};
use crate::merkle::utils::{merkle_root, DataType};
use crate::merkle::Merkleized;
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::extract_fixed_bytes;
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

/// The [generalized Merkle tree index](https://github.com/ethereum/consensus-specs/blob/81f3ea8322aff6b9fb15132d050f8f98b16bdba4/ssz/merkle-proofs.md#generalized-merkle-tree-index)
/// for the next sync committee.
///
/// From [the Altair specifications](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/light-client/sync-protocol.md#constants).
pub const NEXT_SYNC_COMMITTEE_GENERALIZED_INDEX: usize = 55;

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

impl Merkleized for SyncCommittee {
    fn hash_tree_root(&self) -> Result<HashValue, CryptoError> {
        // Get root value for the public key list
        let pubkeys_roots: Vec<HashValue> = self
            .pubkeys
            .iter()
            .map(|pubkey| pubkey.hash_tree_root())
            .collect::<Result<Vec<_>, _>>()?;

        let pubkeys_root = merkle_root(DataType::List(pubkeys_roots))?;

        // Get aggregated public key root value
        let aggregate_pubkey_root = self.aggregate_pubkey.hash_tree_root()?;

        // Combine the root of the public key Merkle tree with the aggregated public key root
        sha2_hash_concat(&pubkeys_root, &aggregate_pubkey_root)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ssz_types::FixedVector;
    use std::env::current_dir;
    use std::fs;
    use tree_hash::TreeHash;
    #[test]
    fn test_ssz_serde_sync_committee() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/SyncCommitteeDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let sync_committee = SyncCommittee::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = sync_committee.to_ssz_bytes();

        assert_eq!(ssz_bytes, test_bytes);
    }

    #[test]
    fn test_sync_committee_hash_tree_root() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/SyncCommitteeDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let sync_committee = SyncCommittee::from_ssz_bytes(&test_bytes).unwrap();

        // Hash for custom implementation
        let hash_tree_root = sync_committee.hash_tree_root().unwrap();

        // Following section mimics derivation of `TreeHash` trait for `SyncCommittee` struct
        // In Lighthouse: https://github.com/sigp/lighthouse/blob/stable/consensus/types/src/sync_committee.rs#L27-L44

        // Pubkey vector hash from `treehash`
        let fixed_vector_pubkeys: FixedVector<PublicKey, ssz_types::typenum::U512> =
            FixedVector::new(sync_committee.pubkeys.to_vec()).unwrap();
        let hash_fixed_vector = fixed_vector_pubkeys.tree_hash_root();

        // Aggregate pubkey hash from `treehash`
        let hash_aggregate_pubkey = sync_committee.aggregate_pubkey.tree_hash_root();

        // `SyncCommittee` hash product by `treehash`
        let mut hasher = tree_hash::MerkleHasher::with_leaves(2);

        hasher.write(hash_fixed_vector.as_bytes()).unwrap();
        hasher.write(hash_aggregate_pubkey.as_bytes()).unwrap();

        let expected_hash = hasher
            .finish()
            .expect("sync committee hash should not have a remaining buffer");

        assert_eq!(&expected_hash.0, hash_tree_root.hash());
    }
}
