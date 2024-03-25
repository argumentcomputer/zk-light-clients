// SPDX-License-Identifier: Apache-2.0, MIT
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Failed to deserialize a valid BLS signature from received bytes")]
    SignatureDeserializationError,
    #[error("Failed to deserialize a valid public key from received bytes")]
    PublicKeyDeserializationError,
}
