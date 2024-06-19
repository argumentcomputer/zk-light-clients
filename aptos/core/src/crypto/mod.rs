// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: BUSL-1.1

//! # Cryptographic Utilities for the Aptos Light Client
//!
//! This module contains cryptographic utilities used by the light client.
//! It is divided into several sub-modules, each with its own specific functionality.
//!
//! ## Sub-modules
//!
//! - `hash`: This sub-module contains the `HashValue` structure and associated methods..
//! - `sig`: This sub-module contains the `Signature` and `PublicKey` structures and their associated methods.
//! - `error`: This sub-module contains the ``CryptoError` error type used throughout the `crypto` module.
//!
//! For more detailed information, users should refer to the specific documentation for each sub-module.
mod error;
pub mod hash;
pub mod sig;
