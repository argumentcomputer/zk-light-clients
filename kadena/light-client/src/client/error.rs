// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: APACHE-2.0

use thiserror::Error;

/// The error type for the `client` module.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Request for endpoint \"{endpoint}\" failed: {source}")]
    Request {
        endpoint: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Error while handling response for endpoint \"{endpoint}\": {source}")]
    Response {
        endpoint: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Could not connect to the given address, {address}")]
    Connection { address: String },
}
