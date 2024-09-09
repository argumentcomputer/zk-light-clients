// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Errors possible while validating data.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid digest length: expected {expected}, got {actual}")]
    DigestLength { expected: usize, actual: usize },
}
