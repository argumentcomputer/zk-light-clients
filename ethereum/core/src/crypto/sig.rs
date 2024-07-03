// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use crate::crypto::error::CryptoError;
use anyhow::Result;
use bls12_381::G1Affine;
use std::cell::OnceCell;

/// Length of a public key in bytes.
pub const PUB_KEY_LEN: usize = 48;

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
}
