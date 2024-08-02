// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

//! Core library for the Aptos light client.
//!
//! This library contains the data structures and utilities used by the light client.
//! It is divided into several modules, each with its own specific functionality.
//!
//! - `aptos_test_utils`: This module contains test utilities for Aptos. It is only included when the `aptos` feature is enabled.
//! - `crypto`: This module contains cryptographic utilities used by the light client.
//! - `merkle`: This module contains data structures and utilities for working with Merkle trees.
//! - `types`: This module contains various data types used by the light client.
#[cfg(feature = "aptos")]
pub mod aptos_test_utils;
pub mod crypto;
pub mod merkle;
pub mod types;
