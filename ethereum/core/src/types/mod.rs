// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

//! # Types Module
//!
//! This module provides the core data structures and types used in the Ethereum Light Client.
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

/// Constant number of validators in the sync committee.
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// A 32-byte array.
pub type Bytes32 = [u8; 32];
