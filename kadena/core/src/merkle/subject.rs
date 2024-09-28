// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::sha512::hash_leaf;
use crate::crypto::hash::HashValue;
use crate::types::error::TypesError;
use crate::types::U32_BYTES_LENGTH;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;

pub const SUBJECT_BASE_BYTES_LENGTH: usize = U32_BYTES_LENGTH;

#[derive(Clone, Debug, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Subject {
    input: String,
}

impl Subject {
    /// Create a new `Subject` with the given input.
    ///
    /// # Arguments
    ///
    ///  * `input` - The input for the subject.
    ///
    /// # Returns
    ///
    /// A new `Subject`.
    pub const fn new(input: String) -> Self {
        Self { input }
    }

    /// Convert the `Subject` to bytes.
    ///
    /// # Returns
    ///
    /// The bytes of the `Subject`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let input_bytes = self.input.as_bytes();

        // Add input length
        bytes.extend_from_slice(&(input_bytes.len() as u32).to_be_bytes());

        // Add input
        bytes.extend_from_slice(input_bytes);

        bytes
    }

    /// Convert bytes to a `Subject`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes to convert.
    ///
    /// # Returns
    ///
    /// The `Subject` represented by the bytes.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < SUBJECT_BASE_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "Subject".to_string(),
                actual: bytes.len(),
                minimum: SUBJECT_BASE_BYTES_LENGTH,
            });
        }

        // Read input length (first 4 bytes)
        let input_length = u32::from_be_bytes(
            bytes[0..U32_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 4 bytes for u32"),
        ) as usize;
        bytes = &bytes[U32_BYTES_LENGTH..];

        if bytes.len() < input_length {
            return Err(TypesError::UnderLength {
                structure: "Subject".to_string(),
                actual: bytes.len(),
                minimum: input_length,
            });
        }

        // Read input
        let input = String::from_utf8(bytes[0..input_length].to_vec()).map_err(|err| {
            TypesError::DeserializationError {
                structure: "Subject".into(),
                source: err.into(),
            }
        })?;

        Ok(Self::new(input))
    }

    /// Hash the `Subject` as a leaf in a Merkle Tree.
    ///
    /// # Returns
    ///
    /// The hash of the `Subject` as a leaf.
    pub fn hash_as_leaf(&self) -> Result<HashValue, CryptoError> {
        hash_leaf(
            &URL_SAFE_NO_PAD
                .decode(self.input.as_bytes())
                .map_err(|err| CryptoError::Base64Error { source: err.into() })?,
        )
    }
}

#[cfg(all(test, feature = "kadena"))]
mod test {
    use crate::merkle::subject::Subject;
    use crate::test_utils::random_string;
    use crate::types::U32_BYTES_LENGTH;

    const STRING_LENGTH: usize = 45;

    #[test]
    fn test_serde_subject() {
        let subject = Subject::new(random_string(STRING_LENGTH));

        let bytes = subject.to_bytes();
        assert_eq!(bytes.len(), U32_BYTES_LENGTH + STRING_LENGTH);

        let deserialized_subject = Subject::from_bytes(&bytes).unwrap();

        assert_eq!(subject, deserialized_subject);
    }
}
