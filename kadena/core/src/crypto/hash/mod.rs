// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::fmt;

pub mod blake2;
pub mod sha512;

/// Size in bytes of a digest in the context of the Kadena chain.
pub const DIGEST_BYTES_LENGTH: usize = 32;

#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct HashValue {
    hash: [u8; DIGEST_BYTES_LENGTH],
}

impl HashValue {
    /// Create a new [`HashValue`] from a byte array.
    pub const fn new(hash: [u8; DIGEST_BYTES_LENGTH]) -> Self {
        HashValue { hash }
    }

    /// Create from a slice (e.g. retrieved from storage).
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes to create the hash from.
    ///
    /// # Returns
    ///
    /// The hash value.
    pub fn from_slice<T: AsRef<[u8]>>(bytes: T) -> Result<Self, CryptoError> {
        <[u8; DIGEST_BYTES_LENGTH]>::try_from(bytes.as_ref())
            .map_err(|_| CryptoError::DigestLength {
                expected: DIGEST_BYTES_LENGTH,
                actual: bytes.as_ref().len(),
            })
            .map(Self::new)
    }

    /// Dumps into a vector.
    ///
    /// # Returns
    ///
    /// The hash value as a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    /// Dumps into a base64 string.
    ///
    /// # Returns
    ///
    /// The hash value as a base64 string.
    pub fn to_base64_str(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.hash)
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

impl fmt::Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashValue(")?;
        <Self as fmt::LowerHex>::fmt(self, f)?;
        write!(f, ")")?;
        Ok(())
    }
}

/// Will print shortened (4 bytes) hash
impl fmt::Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.hash.iter().take(4) {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl AsRef<[u8; DIGEST_BYTES_LENGTH]> for HashValue {
    fn as_ref(&self) -> &[u8; DIGEST_BYTES_LENGTH] {
        &self.hash
    }
}

impl Default for HashValue {
    fn default() -> Self {
        HashValue {
            hash: [0; DIGEST_BYTES_LENGTH],
        }
    }
}
