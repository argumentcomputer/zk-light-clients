// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

//! # Cryptographic Utilities for the Ethereum Light Client
//!
//! This module contains cryptographic utilities used by the light client.
//! It is divided into several sub-modules, each with its own specific functionality.
//!
//! ## Sub-modules
//!
//! - `sig`: This sub-module contains the `Signature` and `PublicKey` structures and their associated methods.
//! - `error`: This sub-module contains the ``CryptoError` error type used throughout the `crypto` module.
//!
//! For more detailed information, users should refer to the specific documentation for each sub-module.

pub mod error;
pub mod sig;
