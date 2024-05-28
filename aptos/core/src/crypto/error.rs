// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Failed to deserialize {structure} from received bytes: {source}")]
    DeserializationError {
        structure: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Failed to decompress data for {structure}")]
    DecompressionError { structure: String },
}
