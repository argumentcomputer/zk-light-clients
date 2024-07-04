// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Errors possible during type conversions.
#[derive(Debug, Error)]
pub enum TypesError {
    #[error("Failed to deserialize {structure}: {source}")]
    DeserializationError {
        structure: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Received data of invalid length for {structure}. Expected {expected}, got {actual}.")]
    InvalidLength {
        structure: String,
        expected: usize,
        actual: usize,
    },
    #[error("Received too much data to deserialize {structure}. Maximum {maximum}, got {actual}.")]
    OverLength {
        structure: String,
        maximum: usize,
        actual: usize,
    },
    #[error(
        "Received too little data to deserialize {structure}. Minimum {minimum}, got {actual}."
    )]
    UnderLength {
        structure: String,
        minimum: usize,
        actual: usize,
    },
}

/// Macro to create a `TypesError::DeserializationError` with the given structure and source.
#[macro_export]
macro_rules! serde_error {
    ($structure:expr, $source:expr) => {
        TypesError::DeserializationError {
            structure: String::from($structure),
            source: $source.into(),
        }
    };
}
