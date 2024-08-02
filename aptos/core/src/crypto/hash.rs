// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Crypto Hash Module
//!
//! This module provides the implementation of cryptographic hash functions and related structures.
//!
//! ## Usage
//!
//! This module is used for creating and manipulating cryptographic hashes in the Aptos codebase.
//! The `CryptoHash` trait should be implemented by any structure that needs to be hashed.
//! The `HashValue` and `HashValueBitIterator` structures provide functionality for working with hash values and their bits.
use anyhow::{anyhow, Result};
use getset::CopyGetters;
use serde::{Deserialize, Serialize};
use std::fmt;

use tiny_keccak::{Hasher, Sha3};

/// A prefix used in the Aptos codebase to begin the salt of every hashable structure.
/// For each structure the salt consists in this global prefix, concatenated
/// with the specified serialization name of the struct.
pub const HASH_PREFIX: &[u8] = b"APTOS::";

/// Length in bytes of a given `HashValue`.
pub const HASH_LENGTH: usize = 32;

/// `CryptoHash` is a trait to implement on types that can be hashed.
pub trait CryptoHash {
    /// Hashes the object and produces a `HashValue`.
    ///
    /// This method should be implemented to hash the structure implementing this trait.
    /// The hash is computed by concatenating `HASH_PREFIX`, the structure's name, and
    /// the bytes resulting from serializing the structure with BCS (Binary Canonical Serialization).
    ///
    /// # Note
    ///
    /// An exception exists for `SparseMerkleInternalHasher` and
    /// `TransactionAccumulatorHasher` that will be hashing the hash of
    /// their children, and not their serialized bytes.
    ///
    /// # Returns
    ///
    /// A `HashValue` representing the hash of the object.
    fn hash(&self) -> HashValue;
}

/// Computes a SHA3 hash of the input prefixed with `HASH_PREFIX`.
///
/// This function takes a byte slice as input, concatenates it with the `HASH_PREFIX`,
/// and returns the SHA3 hash of the result.
///
/// # Arguments
///
/// * `input` - A byte slice to be hashed.
///
/// # Returns
///
/// A byte array of length `HASH_LENGTH` representing the SHA3 hash of the prefixed input.
pub fn prefixed_sha3(input: &[u8]) -> [u8; HASH_LENGTH] {
    hash_data(HASH_PREFIX, vec![input])
}

/// Computes a SHA3 hash of the given tag and data.
///
/// This function takes a tag and a vector of byte slices, hashes the tag and each byte slice using SHA3,
/// and returns the final hash.
///
/// # Arguments
///
/// * `tag` - A byte slice representing the tag to be hashed.
/// * `data` - A vector of byte slices to be hashed.
///
/// # Returns
///
/// A byte array of length `HASH_LENGTH` representing the SHA3 hash of the tag and data.
pub fn hash_data(tag: &[u8], data: Vec<&[u8]>) -> [u8; HASH_LENGTH] {
    let mut hasher = Sha3::v256();
    if !tag.is_empty() {
        hasher.update(tag);
    }
    for d in data {
        hasher.update(d);
    }
    let mut output = [0u8; HASH_LENGTH];
    hasher.finalize(&mut output);
    output
}

/// A structure representing a hash value.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize, Clone, Copy, CopyGetters, Hash)]
pub struct HashValue {
    #[getset(get_copy = "pub(crate)")]
    hash: [u8; HASH_LENGTH],
}

impl HashValue {
    /// Creates a new `HashValue` from a given hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - A byte array of length `HASH_LENGTH` representing the hash value.
    ///
    /// # Returns
    ///
    /// A new `HashValue` instance.
    pub const fn new(hash: [u8; HASH_LENGTH]) -> Self {
        HashValue { hash }
    }

    /// Creates a `HashValue` from a slice (e.g., retrieved from storage).
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice from which to create the `HashValue`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `HashValue` could be created successfully. If the slice has an invalid length,
    /// the `Result` is `Err` with an error message.
    pub fn from_slice<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        <[u8; HASH_LENGTH]>::try_from(bytes.as_ref())
            .map_err(|e| anyhow!("Invalid length: {}", e))
            .map(Self::new)
    }

    /// Returns a `HashValueBitIterator` over all the bits that represent this `HashValue`.
    ///
    /// # Returns
    ///
    /// A `HashValueBitIterator` instance for iterating over the bits of the `HashValue`.
    pub fn iter_bits(&self) -> HashValueBitIterator<'_> {
        HashValueBitIterator::new(self)
    }

    /// Converts the `HashValue` into a vector.
    ///
    /// This method takes the hash value and converts it into a vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the hash value.
    pub fn to_vec(&self) -> Vec<u8> {
        self.hash.to_vec()
    }
}

impl AsRef<[u8; HASH_LENGTH]> for HashValue {
    fn as_ref(&self) -> &[u8; HASH_LENGTH] {
        &self.hash
    }
}

impl fmt::LowerHex for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for byte in &self.hash {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

pub struct HashValueBitIterator<'a> {
    /// The reference to the bytes that represent the `HashValue`.
    hash_bytes: &'a [u8; HASH_LENGTH],
    pos: std::ops::Range<usize>,
    // invariant hash_bytes.len() == HashValue::LENGTH;
    // invariant pos.end == hash_bytes.len() * 8;
}

impl<'a> HashValueBitIterator<'a> {
    /// Constructs a new `HashValueBitIterator` using given `HashValue`.
    fn new(hash_value: &'a HashValue) -> Self {
        HashValueBitIterator {
            hash_bytes: hash_value.as_ref(),
            pos: (0..HASH_LENGTH * 8),
        }
    }

    /// Returns the `index`-th bit in the bytes.
    fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index < HASH_LENGTH * 8); // assumed precondition
        let pos = index / 8;
        let bit = 7 - index % 8;
        (self.hash_bytes[pos] >> bit) & 1 != 0
    }
}

impl<'a> Iterator for HashValueBitIterator<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        self.pos.next().map(|x| self.get_bit(x))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.pos.size_hint()
    }
}

impl<'a> DoubleEndedIterator for HashValueBitIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.pos.next_back().map(|x| self.get_bit(x))
    }
}
