// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Merkle Tree
//!
//! This module provides the utilities to create and manipulate Merkle Trees. It is used to prove
//! the inclusion of a value in a set of values. The Merkle Tree is a binary tree where each leaf
//! node is the hash of a value and each internal node is the hash of its children. The root of the
//! tree is called the Merkle Root and is used to prove the inclusion of a value in the tree.
//!
//! ## Sub-modules
//!
//! - `error`: This sub-module contains the error types that can be returned by the Merkle Tree
//!   utilities.
//! - `proof`: This sub-module contains the utilities to verify Merkle Proofs.
//! - `utils`: This sub-module contains the utilities to manipulate the Merkle Tree.

use crate::crypto::error::CryptoError;
use crate::crypto::hash::HashValue;
pub mod error;
pub mod proof;
pub mod utils;

/// The `Merkleized` trait is implemented by types that can be hashed and represented as a single
/// Merkle Tree root.
pub trait Merkleized {
    /// Hash the object following [SSZ standard](https://www.ssz.dev/show) and return the root of the
    /// Merkle Tree.
    ///
    /// # Returns
    ///
    /// The root of the Merkle Tree.
    fn hash_tree_root(&self) -> Result<HashValue, CryptoError>;
}
