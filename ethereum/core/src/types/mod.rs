// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

//! # Types Module
//!
//! This module provides the core data structures and types used in the Ethereum Light Client. Most
//! types defined in this module implement custom `to_ssz_bytes` and `from_ssz_bytes` methods to handle
//! their serialization and deserialization. This is to reduce dependencies on external libraries.
//!
//! ## Sub-modules
//!
//! - `block`: This sub-module contains all the structures related to block data on the Beacon chain.
//! - `committee`: This sub-module contains all the structures related to committees on the Beacon chain.
//!
//! For more detailed information, users should refer to the specific
//! documentation for each sub-module.

pub mod block;
pub mod committee;
pub mod error;
pub mod utils;

/// Constant number of validators in the sync committee.
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// Length of a bytes32 array.
pub const BYTES_32_LEN: usize = 32;

/// Length of u64 in bytes.
pub const U64_LEN: usize = (u64::BITS / 8) as usize;

/// A 32-byte array.
pub type Bytes32 = [u8; BYTES_32_LEN];

/// Length in bytes for an Ethereum address.
pub const ADDRESS_BYTES_LEN: usize = 20;

/// An ethereum address.
pub type Address = [u8; ADDRESS_BYTES_LEN];
