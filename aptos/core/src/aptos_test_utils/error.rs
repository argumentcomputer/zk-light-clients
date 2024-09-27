// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AptosError {
    #[error("File system error: {source}")]
    FileSystem {
        #[from]
        source: std::io::Error,
    },
    #[error("{0} is unexpectedly None")]
    UnexpectedNone(String),
    #[error("TrustedStateChange error: {source}")]
    TrustedStageChange {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Aptos internal error: {source}")]
    Internal {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Serialization error for {structure}: {source}")]
    Serialization {
        structure: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}
