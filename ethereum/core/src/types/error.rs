// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

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
    #[error("Failed to serialize {structure}: {source}")]
    SerializationError {
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
    #[error("Received data out of bounds for {structure}. Offset: {offset}, Length: {length}.")]
    OutOfBounds {
        structure: String,
        offset: usize,
        length: usize,
    },
    #[error("Error while converting hexadecimal value to a fixed-size array")]
    InvalidHexadecimal,
}

/// Errors possible while manipulating the Light Client store.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error(
        "Failed to initialize store. Expected bootstrap at checkpoint {expected}, got {actual}"
    )]
    InvalidBootstrap { expected: String, actual: String },
    #[error("Error while verifying the current committee in the bootstrap: {source}")]
    InvalidCurrentCommitteeProof {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Error while manipulating Merkle structure: {source}")]
    MerkleError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}

/// Errors possible while verifying the consensus rules.
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Invalid period")]
    InvalidPeriod,
    #[error("Not relevant")]
    NotRelevant,
    #[error("Invalid finality proof")]
    InvalidFinalityProof,
    #[error("Invalid next sync committee proof")]
    InvalidNextSyncCommitteeProof,
    #[error("Error while calculating Merkle root: {source}")]
    MerkleError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Error while verifying signature: {source}")]
    SignatureError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Insufficient signers for the update to be valid. Expected at least one, got 0")]
    InsufficientSigners,
    #[error(
        "Expected to receive a Finality update, but received a value for the next sync committee"
    )]
    ExpectedFinalityUpdate,
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

/// Macro to create a `TypesError::SerializationError` with the given structure and source.
#[macro_export]
macro_rules! serialization_error {
    ($structure:expr, $source:expr) => {
        TypesError::SerializationError {
            structure: String::from($structure),
            source: $source.into(),
        }
    };
}
