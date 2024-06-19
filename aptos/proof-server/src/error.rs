// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: BUSL-1.1

use aptos_lc_core::crypto::hash::HashValue;
use thiserror::Error;

/// Error type for the client.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Error while submitting a request to {endpoint}: {source}")]
    Request {
        endpoint: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Error with payload for endpoint {endpoint}: {source}")]
    ResponsePayload {
        endpoint: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error(
    "Error while trying to verify committee hash predicate, expected {expected:?}, got {actual:?}"
    )]
    VerifierHashInequality {
        expected: HashValue,
        actual: HashValue,
    },
    #[error("Error while trying to verify the proof generated for {0}")]
    Verification(String),
    #[error("Error while trying to join concurrent request: {source}")]
    Join {
        #[source]
        source: tokio::task::JoinError,
    },
    #[error("Error when ratcheting the ClientState: {source}")]
    Ratchet {
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Internal error: {source}")]
    Internal {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}
