// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Beacon module
//!
//! This module contains the data structures used by the Beacon Node to communicate consensus-related
//! data. It is divided into several sub-modules, each with its own specific functionality.
//!
//! ## Sub-modules
//!
//! - `update`: This module contains the data structures passed over RPC for a Light Client to update its
//!   state. It mainly contains the [`ethereum_lc_core::types::update::Update`] structure that contains all the necessary data to attest
//!   of a sync committee change.
//!
//! For more detailed information, users should refer to the specific documentation for each sub-module.
pub mod update;
