// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

use thiserror::Error;

/// The error type for the `crypto` module.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Internal error occurred: {source}")]
    Internal {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}
