// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: APACHE-2.0

use thiserror::Error;

/// Errors possible during type manipulation.
#[derive(Debug, Error)]
pub enum TypesError {
    #[error("Failed to deserialize {structure}: {source}")]
    DeserializationError {
        structure: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Failed to convert {from} to {to}: {source}")]
    ConversionError {
        from: String,
        to: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Received data of invalid length for {structure}. Expected {expected}, got {actual}.")]
    InvalidLength {
        structure: String,
        expected: usize,
        actual: usize,
    },
}

/// Macro to create a `TypesError::DeserializationError` with the given structure and source.
#[macro_export]
macro_rules! deserialization_error {
    ($structure:expr, $source:expr) => {
        TypesError::DeserializationError {
            structure: String::from($structure),
            source: $source.into(),
        }
    };
}
