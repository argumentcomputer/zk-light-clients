// Copyright (c) Argument Computer Corporation
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
//! - `bootstrap`: This module contains the data structures available for a Light Client to bootstrap
//!   to the network.
//! - `committee`: This sub-module contains all the structures related to committees on the Beacon chain.
//! - `signing_data`: This sub-module contains the data structure that represents the message signed
//!    by Validators on the Beacon chain.
//! - `store`: This sub-module contains the data structure representing a Light Client Store containing
//!    the necessary data to verify the consensus.
//! - `update`: This module contains the data structures available for a Light Client to update its
//     state.
//!
//! For more detailed information, users should refer to the specific
//! documentation for each sub-module.

pub mod block;
pub mod bootstrap;
pub mod committee;
pub mod error;
pub mod signing_data;
pub mod store;
pub mod update;
pub mod utils;

/// Length of a bytes32 array.
pub const BYTES_32_LEN: usize = 32;

/// A 32-byte array.
pub type Bytes32 = [u8; BYTES_32_LEN];

/// Length in bytes for an Ethereum address.
pub const ADDRESS_BYTES_LEN: usize = 20;

/// An ethereum address.
pub type Address = [u8; ADDRESS_BYTES_LEN];

/// The [generalized Merkle tree index](https://github.com/ethereum/consensus-specs/blob/81f3ea8322aff6b9fb15132d050f8f98b16bdba4/ssz/merkle-proofs.md#generalized-merkle-tree-index)
/// for finalized block.
///
///
/// From [the Altair specifications](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#constants).
pub const FINALIZED_ROOT_GENERALIZED_INDEX: usize = 105;

/// Number of siblings in a proof for a finalized block root in a merkle tree.
///
/// From [the Altaïr specifications](https://github.com/ethereum/annotated-spec/blob/master/altair/sync-protocol.md#lightclientupdate)
/// and [the Lighthouse implementation](https://github.com/sigp/lighthouse/blob/v5.2.1/consensus/types/src/light_client_update.rs#L32).
pub const FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS: usize = 6;

/// Merkle proof for a finalized block root.
pub type FinalizedRootBranch = [Bytes32; FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS];

/// ForkDigest representing the fork the data originated from.
///
/// From [the phase0 specifications](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#custom-types).
pub type ForkDigest = [u8; 4];
