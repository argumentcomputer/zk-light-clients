// SPDX-License-Identifier: Apache-2.0, MIT
use anyhow::{anyhow, Result};
use getset::CopyGetters;
use serde::{Deserialize, Serialize};
use std::fmt;

use tiny_keccak::{Hasher, Sha3};
pub const HASH_PREFIX: &[u8] = b"APTOS::";
pub const HASH_LENGTH: usize = 32;

pub trait CryptoHash {
    /// Hashes the object and produces a `HashValue`.
    fn hash(&self) -> HashValue;
}

pub fn prefixed_sha3(input: &[u8]) -> [u8; HASH_LENGTH] {
    let mut sha3 = Sha3::v256();
    let salt: Vec<u8> = [HASH_PREFIX, input].concat();
    sha3.update(&salt);
    let mut output = [0u8; HASH_LENGTH];
    sha3.finalize(&mut output);
    output
}

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

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize, Clone, Copy, CopyGetters, Hash)]
pub struct HashValue {
    #[getset(get_copy = "pub(crate)")]
    hash: [u8; HASH_LENGTH],
}

impl HashValue {
    pub const fn new(hash: [u8; HASH_LENGTH]) -> Self {
        HashValue { hash }
    }

    /// Create from a slice (e.g. retrieved from storage).
    pub fn from_slice<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        <[u8; HASH_LENGTH]>::try_from(bytes.as_ref())
            .map_err(|e| anyhow!("Invalid length: {}", e))
            .map(Self::new)
    }

    pub fn from_human_readable(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex).unwrap();
        Ok(HashValue::new(bytes.try_into().unwrap()))
    }

    /// Returns a `HashValueBitIterator` over all the bits that represent this `HashValue`.
    pub fn iter_bits(&self) -> HashValueBitIterator<'_> {
        HashValueBitIterator::new(self)
    }

    /// Dumps into a vector.
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
    hash_bytes: &'a [u8],
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
        debug_assert_eq!(self.hash_bytes.len(), HASH_LENGTH); // invariant
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
