// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use crate::crypto::error::CryptoError;
use crate::types::error::TypesError;
use anyhow::Result;
use bls12_381::{multi_miller_loop, G1Affine, G2Affine, G2Prepared, Gt};
use std::cell::OnceCell;

/// Length of a public key in bytes.
pub const PUB_KEY_LEN: usize = 48;

/// Length of a signature in bytes.
pub const SIG_LEN: usize = 96;

/// A structure representing a public key.
///
/// The public key is represented as a compressed byte array and an optional `G1Affine` point.
/// The `G1Affine` point is computed from the compressed byte array when needed.
#[derive(Clone, Debug, PartialEq, Eq)]

pub struct PublicKey {
    compressed_pubkey: [u8; PUB_KEY_LEN],
    pubkey: OnceCell<G1Affine>,
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            compressed_pubkey: [0u8; PUB_KEY_LEN],
            pubkey: OnceCell::new(),
        }
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
    fn pubkey(&self) -> &G1Affine {
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
    pub fn aggregate(pubkeys: &[&Self]) -> Result<PublicKey, CryptoError> {
        let aggregate = pubkeys
            .iter()
            .fold(G1Affine::identity(), |acc, pk| acc.add_affine(pk.pubkey()));

        let pubkey = OnceCell::new();
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
            pubkey: OnceCell::new(),
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
    pub fn verify(&self, _msg: &[u8], pubkey: &PublicKey) -> Result<(), CryptoError> {
        // TODO replace per the proper hash when implementing signature verification
        let msg = G2Prepared::from(G2Affine::identity());
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
        let sig = G2Affine::from_compressed_unchecked(&bytes.try_into().unwrap()).unwrap();

        Ok(Self { sig })
    }
}
