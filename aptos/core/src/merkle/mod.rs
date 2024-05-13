//! # Merkle Tree Module
//!
//! This module provides the structures and functions necessary for handling Merkle Trees in the Aptos Light Client.
//!
//! ## Sub-modules
//!
//! - `node`: This sub-module contains the `SparseMerkleNode` structure and associated methods. It is used to represent nodes in the Sparse Merkle Tree and the Transaction Accumulator.
//! - `sparse_proof`: This sub-module contains the `SparseMerkleProof` structure and associated methods. It is used to represent and verify proofs in the Sparse Merkle Tree.
//! - `transaction_proof`: This sub-module contains the `TransactionAccumulatorProof` structure and associated methods. It is used to represent and verify proofs in the Transaction Accumulator.
//!
//! For more detailed information, users should refer to the specific documentation for each sub-module.

// SPDX-License-Identifier: Apache-2.0, MIT
pub mod node;
pub mod sparse_proof;
pub mod transaction_proof;
