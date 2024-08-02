// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: APACHE-2.0

//! # Ethereum Light Client Core
//!
//! This crate provides the core types and utilities that are leveraged when dealing with data from
//! the Ethereum network. It is divided into several sub-modules, each with its own specific functionality.
//!
//! ## Sub-modules
//!
//! - `crypto`: This sub-module contains the cryptographic utilities used by the Light Client.
//! - `merkle`: This sub-module contains the utilities to generate and verify Merkle proofs.
//! - `test_utils`: This sub-module contains utilities to help with testing the Light Client.
//! - `types`: This sub-module contains the types and utilities necessary to prove sync committee changes
//!   and value inclusion in the state of the chain.
//!
//! For more detailed information, users should refer to the specific documentation for each sub-module.

pub mod crypto;
pub mod merkle;
#[cfg(feature = "ethereum")]
pub mod test_utils;
pub mod types;
