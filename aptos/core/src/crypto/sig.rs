//! # Crypto Signature Module
//!
//! This module provides the implementation of cryptographic signature functions and related structures.
//! It is part of the `crypto` module in the `core` library of the Aptos project.
//!
//! ## Usage
//!
//! This module is used for creating, manipulating, and verifying cryptographic signatures in the Aptos codebase.
//! The `PublicKey`, `Signature`, and `AggregateSignature` structures provide functionality for working with public keys and signatures.

// SPDX-License-Identifier: Apache-2.0, MIT

use crate::crypto::error::CryptoError;
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::{read_leb128, write_leb128};
use anyhow::Result;
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G2Affine, G2Prepared, G2Projective, Gt};
use bytes::{Buf, BufMut, BytesMut};
use getset::Getters;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cell::OnceCell;

/// Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
const BUCKET_SIZE: usize = 8;

/// BLS DST for hashing to G2.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Length of a public key in bytes.
pub const PUB_KEY_LEN: usize = 48;

/// Length of a signature in bytes.
pub const SIG_LEN: usize = 96;

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
    pub fn aggregate(pubkeys: &[&Self]) -> Result<PublicKey> {
        let aggregate = pubkeys
            .iter()
            .fold(G1Affine::identity(), |acc, pk| acc.add_affine(pk.pubkey()));

        let pubkey = OnceCell::new();
        pubkey.set(aggregate).unwrap();

        Ok(PublicKey {
            compressed_pubkey: [0u8; PUB_KEY_LEN],
            pubkey,
        })
    }

    /// Converts the `PublicKey` into a vector of bytes, following a BCS (Binary Canonical Serialization) standard.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        let pub_key_bytes = self.compressed_pubkey.as_ref();

        bytes.put_slice(&write_leb128(pub_key_bytes.len() as u64));
        bytes.put_slice(pub_key_bytes);
        bytes.to_vec()
    }

    /// Creates a `PublicKey` from a slice of bytes, following a BCS
    /// (Binary Canonical Serialization) standard.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice from which to create the `PublicKey`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `PublicKey` could be created successfully. If the slice has an invalid length,
    /// the `Result` is `Err` with an error message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != PUB_KEY_LEN {
            return Err(serde_error!("PublicKey", "Invalid public key byte length"));
        }

        let bytes_fixed =
            <&[u8; PUB_KEY_LEN]>::try_from(bytes).map_err(|e| serde_error!("PublicKey", e))?;

        Ok(Self {
            compressed_pubkey: *bytes_fixed,
            pubkey: OnceCell::new(),
        })
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "PublicKey",
            serde_bytes::Bytes::new(&self.compressed_pubkey),
        )
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // In order to preserve the Serde data model and help analysis tools,
        // make sure to wrap our value in a container with the same name
        // as the original type.
        #[derive(Deserialize, Debug)]
        #[serde(rename = "PublicKey")]
        struct Value<'a>(&'a [u8]);

        let value = Value::deserialize(deserializer)?;
        PublicKey::try_from(value.0)
            .map_err(|s| <D::Error as Error>::custom(format!("{} with {}", s, "PublicKey")))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            compressed_pubkey: <[u8; PUB_KEY_LEN]>::try_from(bytes).map_err(|e| {
                CryptoError::DeserializationError {
                    structure: String::from("PublicKey"),
                    source: e.into(),
                }
            })?,
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

    /// Converts the `Signature` into a vector of bytes, following a BCS
    /// (Binary Canonical Serialization) standard.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        let sig_bytes = self.sig.to_compressed();

        bytes.put_slice(&write_leb128(sig_bytes.len() as u64));
        bytes.put_slice(&sig_bytes);
        bytes.to_vec()
    }

    /// Creates a `Signature` from a slice of bytes, following a BCS
    /// (Binary Canonical Serialization) standard.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice from which to create the `Signature`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `Signature` could be created
    /// successfully. If the slice has an invalid length, the `Result`
    /// is `Err` with a `TypesError`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != SIG_LEN {
            return Err(serde_error!("Signature", "Invalid signature byte length"));
        }

        let bytes_fixed =
            <&[u8; SIG_LEN]>::try_from(bytes).map_err(|e| serde_error!("PublicKey", e))?;

        let decompressed = G2Affine::from_compressed(bytes_fixed);

        if decompressed.is_none().into() {
            return Err(serde_error!(
                "PublicKey",
                "G2Affine::from_compressed returned None"
            ));
        }

        Ok(Self {
            sig: decompressed.unwrap(),
        })
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "Signature",
            serde_bytes::Bytes::new(self.sig.to_compressed().as_slice()),
        )
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // In order to preserve the Serde data model and help analysis tools,
        // make sure to wrap our value in a container with the same name
        // as the original type.
        #[derive(Deserialize, Debug)]
        #[serde(rename = "Signature")]
        struct Value<'a>(&'a [u8]);

        let value = Value::deserialize(deserializer)?;
        Signature::try_from(value.0)
            .map_err(|s| <D::Error as Error>::custom(format!("{} with {}", s, "Signature")))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = CryptoError;

    /// Deserializes a Signature from a sequence of bytes.
    ///
    /// WARNING: Does NOT subgroup-check the signature! Instead, this will be done implicitly when
    /// verifying the signature.
    fn try_from(bytes: &[u8]) -> Result<Signature, Self::Error> {
        let g2_affine_option: Option<G2Affine> =
            G2Affine::from_compressed(<&[u8; SIG_LEN]>::try_from(bytes).map_err(|e| {
                CryptoError::DeserializationError {
                    structure: String::from("Signature"),
                    source: e.into(),
                }
            })?)
            .into();

        if let Some(g2_affine) = g2_affine_option {
            Ok(Self { sig: g2_affine })
        } else {
            Err(CryptoError::DecompressionError {
                structure: String::from("Signature"),
            })
        }
    }
}

/// A structure representing a bit vector.
///
/// The bit vector is represented as a vector of bytes, where each byte is used as a bucket of 8 bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BitVec {
    #[serde(with = "serde_bytes")]
    inner: Vec<u8>,
}

impl BitVec {
    /// Returns the number of buckets required for a given number of bits.
    ///
    /// # Arguments
    ///
    /// * `num_bits` - The number of bits for which to calculate the required number of buckets.
    ///
    /// # Returns
    ///
    /// The number of buckets required to store the given number of bits.
    pub fn required_buckets(num_bits: u16) -> usize {
        num_bits
            .checked_sub(1)
            .map_or(0, |pos| pos as usize / BUCKET_SIZE + 1)
    }

    /// Checks if the bit at a given position is set.
    ///
    /// # Arguments
    ///
    /// * `pos` - The position of the bit to check.
    ///
    /// # Returns
    ///
    /// `true` if the bit at the given position is set, `false` otherwise.
    #[inline]
    pub fn is_set(&self, pos: u16) -> bool {
        // This is optimised to: let bucket = pos >> 3;
        let bucket: usize = pos as usize / BUCKET_SIZE;
        if self.inner.len() <= bucket {
            return false;
        }
        // This is optimized to: let bucket_pos = pos | 0x07;
        let bucket_pos = pos as usize - (bucket * BUCKET_SIZE);
        (self.inner[bucket] & (0b1000_0000 >> bucket_pos as u8)) != 0
    }

    /// Returns the number of buckets in the bit vector.
    ///
    /// # Returns
    ///
    /// The number of buckets in the bit vector.
    pub fn num_buckets(&self) -> usize {
        self.inner.len()
    }

    /// Returns an `Iterator` over all '1' bit indexes.
    ///
    /// # Returns
    ///
    /// An `Iterator` over all '1' bit indexes.
    pub fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.inner.len() * BUCKET_SIZE).filter(move |idx| self.is_set(*idx as u16))
    }

    /// Returns the index of the last set bit.
    ///
    /// # Returns
    ///
    /// The index of the last set bit, or `None` if no bits are set.
    pub fn last_set_bit(&self) -> Option<u16> {
        self.inner
            .iter()
            .rev()
            .enumerate()
            .find(|(_, byte)| byte != &&0u8)
            .map(|(i, byte)| {
                (8 * (self.inner.len() - i) - byte.trailing_zeros() as usize - 1) as u16
            })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();

        bytes.put_u8(self.inner.len() as u8);
        bytes.put_slice(&self.inner);
        bytes.to_vec()
    }

    /// Creates a `BitVec` from a slice of bytes, following a BCS
    /// (Binary Canonical Serialization) standard.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice from which to create the `BitVec`.
    ///
    /// # Returns
    ///
    /// A `BitVec` instance created from the given byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }
}

impl<'de> Deserialize<'de> for BitVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "BitVec")]
        struct RawData {
            #[serde(with = "serde_bytes")]
            inner: Vec<u8>,
        }
        let v = RawData::deserialize(deserializer)?.inner;
        // Every u8 is used as a bucket of 8 bits. Total max buckets = 65536 / 8 = 8192.
        // https://github.com/aptos-labs/aptos-core/blob/main/crates/aptos-bitvec/src/lib.rs#L19
        if v.len() > 8192 {
            return Err(D::Error::custom(format!("BitVec too long: {}", v.len())));
        }
        Ok(BitVec { inner: v })
    }
}

// Example structure for an aggregate signature.
#[derive(Debug, Clone, PartialEq, Eq, Getters, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct AggregateSignature {
    validator_bitmask: BitVec,
    sig: Option<Signature>,
}

impl AggregateSignature {
    /// Converts the `AggregateSignature` into a vector of bytes, following a BCS
    /// (Binary Canonical Serialization) standard.
    ///
    /// This method takes the aggregate signature and converts it into a vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the aggregate signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.validator_bitmask.to_bytes());
        if let Some(sig) = &self.sig {
            bytes.put_u8(1); // Indicate that there is a signature
            bytes.put_slice(&sig.to_bytes());
        } else {
            bytes.put_u8(0); // Indicate that there is no signature
        }
        bytes.to_vec()
    }

    /// Creates an `AggregateSignature` from a slice of bytes, following a BCS
    /// (Binary Canonical Serialization) standard.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice from which to create the `AggregateSignature`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `AggregateSignature` could be created
    /// successfully. If the slice has an invalid length, the `Result`
    /// is `Err` with a `TypesError`.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let bitvec_len = bytes.get_u8() as usize;

        let validator_bitmask = BitVec::from_bytes(
            bytes
                .chunk()
                .get(..bitvec_len)
                .ok_or_else(|| serde_error!("AggregateSignature", "Not enough data for BitVec"))?,
        );

        bytes.advance(bitvec_len);

        let sig = match bytes.get_u8() {
            1 => {
                let (slice_len, bytes_read) = read_leb128(bytes).map_err(|e| {
                    serde_error!(
                        "AggregateSignature",
                        format!("Failed to read length of public_key: {e}")
                    )
                })?;
                bytes.advance(bytes_read);

                let sig =
                    Signature::from_bytes(bytes.chunk().get(..slice_len as usize).ok_or_else(
                        || serde_error!("AggregateSignature", "Not enough data for Signature"),
                    )?)?;
                bytes.advance(slice_len as usize);

                Some(sig)
            }
            _ => None,
        };

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "AggregateSignature",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self {
            validator_bitmask,
            sig,
        })
    }
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    #[test]
    fn test_bytes_conversion() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::crypto::sig::AggregateSignature;

        let mut aptos_wrapper = AptosWrapper::new(2, 130, 130).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let latest_li = aptos_wrapper.get_latest_li().unwrap();
        let agg_sig = latest_li.signatures();

        let bytes = bcs::to_bytes(&agg_sig).unwrap();

        let intern_agg_sig = AggregateSignature::from_bytes(&bytes).unwrap();
        let intern_bytes = intern_agg_sig.to_bytes();

        assert_eq!(bytes, intern_bytes);
    }
}
