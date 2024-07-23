// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::{sha2_hash, HashValue, HASH_LENGTH};
use crate::merkle::Merkleized;
use crate::types::committee::SYNC_COMMITTEE_SIZE;
use crate::types::error::TypesError;
use crate::types::utils::{pack_bits, unpack_bits};
use crate::{deserialization_error, serialization_error};
use anyhow::Result;
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G2Affine, G2Prepared, G2Projective, Gt};
use getset::Getters;
use std::result;
use std::sync::OnceLock;
#[cfg(test)]
use tree_hash::{TreeHash, TreeHashType};

/// Length of a public key in bytes.
pub const PUB_KEY_LEN: usize = 48;

/// Length of a signature in bytes.
pub const SIG_LEN: usize = 96;

/// BLS DST for hashing to G2.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Computes a hash of the given message to a `G2Projective` point.
///
/// This function uses the `HashToCurve` trait implemented for `G2Projective` to hash the message.
///
/// # Arguments
///
/// * `msg` - A byte slice representing the message to be hashed.
///
/// # Returns
///
/// A `G2Projective` point representing the hash of the message.
#[must_use]
pub fn hash(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DST)
}

/// A structure representing a public key.
///
/// The public key is represented as a compressed byte array and an optional `G1Affine` point.
/// The `G1Affine` point is computed from the compressed byte array when needed.
#[derive(Clone, Debug, PartialEq, Eq, Getters)]
pub struct PublicKey {
    #[getset(get = "pub")]
    compressed_pubkey: [u8; PUB_KEY_LEN],
    pubkey: OnceLock<G1Affine>,
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            compressed_pubkey: [0u8; PUB_KEY_LEN],
            pubkey: OnceLock::new(),
        }
    }
}

impl Merkleized for PublicKey {
    fn hash_tree_root(&self) -> Result<HashValue, CryptoError> {
        let mut bytes = [0; HASH_LENGTH * 2];
        bytes[0..PUB_KEY_LEN].copy_from_slice(&self.compressed_pubkey);
        sha2_hash(&bytes)
    }
}

// From https://github.com/sigp/lighthouse/blob/stable/crypto/bls/src/macros.rs#L4-L27
#[cfg(test)]
impl TreeHash for PublicKey {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let values_per_chunk = tree_hash::BYTES_PER_CHUNK;
        let minimum_chunk_count = (PUB_KEY_LEN + values_per_chunk - 1) / values_per_chunk;
        tree_hash::merkle_root(self.compressed_pubkey(), minimum_chunk_count)
    }
}

impl PublicKey {
    /// Returns the `G1Affine` point representing the public key.
    ///
    /// If the `G1Affine` point has not been computed yet, it is computed from the compressed byte array and stored.
    ///
    /// # Returns
    ///
    /// A `G1Affine` point representing the public key.
    ///
    /// # Note
    ///
    // All public key data we receive are in a message signed by validators of a (prior) epoch.
    // We assume those signers check against rogue key attacks before signing those keys.
    #[inline]
    pub fn pubkey(&self) -> &G1Affine {
        self.pubkey
            .get_or_init(|| G1Affine::from_compressed_unchecked(&self.compressed_pubkey).unwrap())
    }

    /// Aggregates a vector of public keys into a single public key.
    ///
    /// # Arguments
    ///
    /// * `pubkeys` - A slice of references to `PublicKey` instances to be aggregated.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the public keys could be aggregated successfully. If the aggregation fails,
    /// the `Result` is `Err` with an error message.
    pub fn aggregate(pubkeys: &[Self]) -> Result<Self, CryptoError> {
        let aggregate = pubkeys
            .iter()
            .fold(G1Affine::identity(), |acc, pk| acc.add_affine(pk.pubkey()));

        let pubkey = OnceLock::new();
        pubkey.set(aggregate).map_err(|_| CryptoError::Internal {
            source: "Failed to set the aggregate public key value in the cell.".into(),
        })?;

        Ok(PublicKey {
            compressed_pubkey: [0u8; PUB_KEY_LEN],
            pubkey,
        })
    }

    /// Serialize a `PublicKey` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `PublicKey` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend_from_slice(&self.compressed_pubkey);

        bytes
    }

    /// Deserialize a `PublicKey` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `PublicKey` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `PublicKey` data structure or a `TypesError`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != PUB_KEY_LEN {
            return Err(TypesError::InvalidLength {
                structure: "PublicKey".into(),
                expected: PUB_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let mut compressed_pubkey = [0u8; PUB_KEY_LEN];
        compressed_pubkey.copy_from_slice(bytes);

        Ok(Self {
            compressed_pubkey,
            pubkey: OnceLock::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) sig: G2Affine,
}

impl Signature {
    /// Verifies the signature against a given message and public key.
    ///
    /// # Arguments
    ///
    /// * `msg` - A byte slice representing the message against which to verify the signature.
    /// * `pubkey` - A mutable reference to the `PublicKey` against which to verify the signature.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the signature is valid. If the signature is invalid,
    /// the `Result` is `Err` with a `CryptoError`.
    pub fn verify(&self, msg: &[u8], pubkey: &PublicKey) -> Result<(), CryptoError> {
        let msg = G2Prepared::from(G2Affine::from(hash(msg)));
        let g1 = G1Affine::generator();

        let ml_terms = [(&-g1, &G2Prepared::from(self.sig)), (pubkey.pubkey(), &msg)];

        if multi_miller_loop(&ml_terms).final_exponentiation() == Gt::identity() {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    /// Serialize a `Signature` data structure to an SSZ formatted vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `Signature` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend_from_slice(&self.sig.to_compressed());

        bytes
    }

    /// Deserialize a `Signature` data structure from SSZ formatted bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `Signature` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `Signature` data structure or a `TypesError`.
    ///
    /// # Errors
    ///
    /// Returns a `TypesError` if the received bytes are not of the correct length (96 bytes).
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        // Check that the received bytes are of proper size
        if bytes.len() != SIG_LEN {
            return Err(TypesError::InvalidLength {
                structure: "Signature".into(),
                expected: SIG_LEN,
                actual: bytes.len(),
            });
        }

        // Decompress G2 point
        let decompressed =
            G2Affine::from_compressed_unchecked(&bytes.try_into().map_err(|_| {
                deserialization_error!(
                    "Signature",
                    "Could not convert the received bytes in G2 point compressed shape"
                )
            })?);

        if decompressed.is_none().into() {
            return Err(deserialization_error!(
                "Signature",
                "G2Affine::from_compressed returned None"
            ));
        }

        Ok(Self {
            sig: decompressed.unwrap(),
        })
    }
}

/// Size in SSZ serialized bytes for a [`SyncAggregate`].
pub const SYNC_AGGREGATE_BYTES_LEN: usize = SYNC_COMMITTEE_SIZE / 8 + SIG_LEN;

/// Structure that represents an aggregated signature on the Beacon chain. It contains the validator
/// index who signed the message as bits and the actual signature.
///
/// From [the Altaïr specifications](https://github.com/ethereum/consensus-specs/blob/81f3ea8322aff6b9fb15132d050f8f98b16bdba4/specs/altair/beacon-chain.md#syncaggregate).
#[derive(Debug, Clone, Eq, PartialEq, Getters)]
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
    pub fn to_ssz_bytes(&self) -> result::Result<Vec<u8>, TypesError> {
        let mut bytes = Vec::new();

        // Serialize sync_committee_bits as a packed bit array
        let packed_bits = pack_bits(&self.sync_committee_bits).map_err(|e| {
            serialization_error!("SyncAggregate", format!("Could not pack bits: {:?}", e))
        })?;
        bytes.extend_from_slice(&packed_bits);

        // Serialize sync_committee_signature
        bytes.extend_from_slice(&self.sync_committee_signature.to_ssz_bytes());

        Ok(bytes)
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
    pub fn from_ssz_bytes(bytes: &[u8]) -> result::Result<Self, TypesError> {
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
                    deserialization_error!(
                        "SyncAggregate",
                        "Could not deserialize sync_committee_bits"
                    )
                })?;

        // Deserialize sync_committee_signature
        let sync_committee_signature: Signature =
            Signature::from_ssz_bytes(&bytes[SYNC_COMMITTEE_SIZE / 8..])?;

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
    fn test_ssz_serde_sync_aggregate() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/SyncAggregateDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let execution_block_header = SyncAggregate::from_ssz_bytes(&test_bytes).unwrap();

        let ssz_bytes = execution_block_header.to_ssz_bytes().unwrap();

        assert_eq!(ssz_bytes, test_bytes);
    }
}
