// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: APACHE-2.0

//! # Types module
//!
//! This module contains the types and utilities necessary to leverage data from  the remote services.
//! It is divided into several sub-modules, each with its own specific functionality.
//!
//! Some types in this module implement custom `to_ssz_bytes` and `from_ssz_bytes` methods to
//! handle their serialization and deserialization. This is to reduce dependencies on external
//! libraries.
//!
//! ## Sub-modules
//!
//! - `beacon`: This sub-module contains the data structures used by the Beacon Node.
//! - `checkpoint`: This sub-module contains the data structures used by the Checkpoint service.
//! - `network`: This sub-module contains the data structures that serves as payload for the Proof Server.
//! - `storage`: This sub-module contains the data structures used by the RPC Provider.
//!
//! For more detailed information, users should refer to the specific documentation for each sub-module.

pub mod beacon;
pub mod checkpoint;
pub mod network;
pub mod storage;
