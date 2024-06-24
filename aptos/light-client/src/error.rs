// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: BUSL-1.1

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum LightClientError {
    #[error("[{program}] Failed to prove: {source}")]
    ProvingError {
        program: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}
