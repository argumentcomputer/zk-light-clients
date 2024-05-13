//! # Sparse Merkle Proof Module
//!
//! This module provides the structures and functions
//! necessary for handling Sparse Merkle Proofs in a Merkle Tree.
//!
//! ## Usage
//!
//! The `SparseMerkleProof` structure is used to authenticate
//! whether a given leaf exists in the Sparse Merkle Tree
//! or not. It contains a leaf node and a list of sibling nodes.
//! The siblings are ordered from the bottom level to the
//! root level of the Sparse Merkle Tree.
//!
//! The `SparseMerkleProof` structure provides methods
//! for verifying the proof (`verify_by_hash`), converting
//! the proof to bytes (`to_bytes`), and creating a proof
//! from bytes (`from_bytes`). These methods are used
//! to authenticate the existence of a leaf in the Sparse
//! Merkle Tree, serialize the proof for storage or
//! transmission, and deserialize the proof for verification,
//! respectively.

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{CryptoHash, HashValue, HASH_LENGTH};
use crate::merkle::node::{MerkleInternalNode, SparseMerkleInternalHasher, SparseMerkleLeafNode};
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::{read_leb128, write_leb128};
use anyhow::{ensure, Result};
use bytes::{Buf, BufMut, BytesMut};
use getset::Getters;
use serde::{Deserialize, Serialize};

/// `SparseMerkleProof` is a structure representing a proof
/// in a Sparse Merkle Tree.
///
/// Each `SparseMerkleProof` contains an optional leaf
/// node and a list of sibling nodes. The siblings are ordered
/// from the bottom level to the root level of the Sparse
/// Merkle Tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct SparseMerkleProof {
    /// This proof can be used to authenticate whether a given leaf exists in the tree or not.
    ///     - If this is `Some(leaf_node)`
    ///         - If `leaf_node.key` equals requested key, this is an inclusion proof and
    ///           `leaf_node.value_hash` equals the hash of the corresponding account blob.
    ///         - Otherwise this is a non-inclusion proof, which we do not handle.
    ///     - If this is `None`, this is also a non-inclusion proof, which we do not handle in the light client.
    leaf: Option<SparseMerkleLeafNode>,

    /// All siblings in this proof, including the default ones. Siblings are ordered from the bottom
    /// level to the root level.
    siblings: Vec<HashValue>,
}

impl SparseMerkleProof {
    /// Verifies an element whose key is `element_key` and
    /// value is authenticated by `element_hash` exists in
    /// the Sparse Merkle Tree using the provided proof.
    ///
    /// # Arguments
    ///
    /// * `expected_root_hash: HashValue` - The expected root hash of the Sparse Merkle Tree.
    /// * `element_key: HashValue` - The key of the element to verify.
    /// * `element_hash: HashValue` - The hash of the element to verify.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the element exists in
    /// the Sparse Merkle Tree and the proof is valid, and
    /// `Err` otherwise.
    #[allow(dead_code)]
    pub fn verify_by_hash(
        &self,
        expected_root_hash: HashValue,
        element_key: HashValue,
        element_hash: HashValue,
    ) -> Result<HashValue> {
        ensure!(
            self.siblings.len() <= HASH_LENGTH * 8,
            "Sparse Merkle Tree proof has more than {} ({}) siblings.",
            256,
            self.siblings.len(),
        );

        // Proof need to contain leaf if proof of inclusion
        let leaf = self.leaf.unwrap();
        ensure!(
            element_key == leaf.key(),
            "Keys do not match. Key in proof: {:x}. Expected key: {:x}. \
             Element hash: {:x}. Value hash in proof {:x}",
            leaf.key(),
            element_key,
            element_hash,
            leaf.value_hash()
        );

        ensure!(
            element_hash == leaf.value_hash(),
            "Value hashes do not match for key {:x}.",
            element_key
        );

        let reconstructed_root = self
            .siblings
            .iter()
            .zip(
                element_key
                    .iter_bits()
                    .rev()
                    .skip(HASH_LENGTH * 8 - self.siblings.len()),
            )
            .fold(leaf.hash(), accumulator_update);

        ensure!(
            reconstructed_root == expected_root_hash,
            "Root hash mismatch. Expected root hash: {:x}. Computed root hash: {:x}",
            expected_root_hash,
            reconstructed_root
        );

        Ok(reconstructed_root)
    }

    /// Converts the `SparseMerkleProof` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `SparseMerkleProof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        match &self.leaf {
            Some(node) => {
                bytes.put_u8(1);
                bytes.put_slice(&node.to_bytes());
            }
            None => {
                bytes.put_u8(0);
            }
        }
        bytes.put_slice(&write_leb128(self.siblings.len() as u64));
        for sibling in &self.siblings {
            bytes.put_slice(sibling.as_ref());
        }
        bytes.to_vec()
    }

    /// Creates a `SparseMerkleProof` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create
    /// the `SparseMerkleProof`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `SparseMerkleProof`
    /// could be successfully created, and `Err` otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let mut buf = bytes;

        let leaf = match buf.get_u8() {
            1 => {
                let node = SparseMerkleLeafNode::from_bytes(
                    buf.chunk().get(..2 * HASH_LENGTH).ok_or_else(|| {
                        serde_error!("SparseMerkleProof", "Not enough data for leaf")
                    })?,
                )
                .map_err(|e| serde_error!("SparseMerkleProof", e))?;
                buf.advance(2 * HASH_LENGTH);

                Some(node)
            }
            _ => None,
        };

        let (num_siblings, len) =
            read_leb128(buf.chunk()).map_err(|e| serde_error!("SparseMerkleProof", e))?;
        buf.advance(len);

        let mut siblings = Vec::new();
        for _ in 0..num_siblings {
            let sibling =
                HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                    serde_error!("SparseMerkleProof", "Not enough data for sibling")
                })?)
                .map_err(|e| serde_error!("SparseMerkleProof", e))?;
            buf.advance(HASH_LENGTH);
            siblings.push(sibling);
        }

        if buf.remaining() != 0 {
            return Err(serde_error!(
                "SparseMerkleProof",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self { leaf, siblings })
    }
}

/// Updates the accumulator hash during proof verification.
///
/// # Arguments
///
/// * `acc_hash: HashValue` - The current accumulator hash.
/// * `(sibling_hash, bit): (&HashValue, bool)` - The hash of the
/// sibling node and a boolean indicating whether the sibling is on the right.
///
/// # Returns
///
/// A `HashValue` representing the updated accumulator hash.
fn accumulator_update(acc_hash: HashValue, (sibling_hash, bit): (&HashValue, bool)) -> HashValue {
    if bit {
        MerkleInternalNode::<SparseMerkleInternalHasher>::new(*sibling_hash, acc_hash).hash()
    } else {
        MerkleInternalNode::<SparseMerkleInternalHasher>::new(acc_hash, *sibling_hash).hash()
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::hash::CryptoHash;
    use crate::crypto::hash::{hash_data, HashValue, HASH_LENGTH};
    use crate::merkle::node::{
        MerkleInternalNode, SparseMerkleInternalHasher, SparseMerkleLeafNode,
    };
    use crate::merkle::sparse_proof::SparseMerkleProof;

    #[test]
    fn test_verify_proof_simple() {
        // Leaf and root hashes
        let a_leaf_hash = hash_data(&[], vec!["a".as_bytes()]);
        let b_leaf_hash = hash_data(&[], vec!["b".as_bytes()]);
        let c_leaf_hash = hash_data(&[], vec!["c".as_bytes()]);
        let d_leaf_hash = hash_data(&[], vec!["d".as_bytes()]);

        let cd_leaf_hash = hash_data(&[], vec![c_leaf_hash.as_slice(), d_leaf_hash.as_slice()]);

        let leaf_node = SparseMerkleLeafNode::new(
            HashValue::from_slice([
                128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ])
            .unwrap(),
            HashValue::from_slice(a_leaf_hash).unwrap(),
        );

        let siblings = vec![
            HashValue::from_slice(b_leaf_hash).unwrap(),
            HashValue::from_slice(cd_leaf_hash).unwrap(),
        ];

        let proof = SparseMerkleProof {
            leaf: Some(leaf_node),
            siblings: siblings.clone(),
        };

        let key = leaf_node.key();
        let value_hash = leaf_node.value_hash();
        let expected_root_hash = siblings
            .iter()
            .zip(key.iter_bits().rev().skip(HASH_LENGTH * 8 - siblings.len()))
            .fold(leaf_node.hash(), |acc_hash, (sibling_hash, bit)| {
                if bit {
                    MerkleInternalNode::<SparseMerkleInternalHasher>::new(*sibling_hash, acc_hash)
                        .hash()
                } else {
                    MerkleInternalNode::<SparseMerkleInternalHasher>::new(acc_hash, *sibling_hash)
                        .hash()
                }
            });

        proof
            .verify_by_hash(expected_root_hash, key, value_hash)
            .unwrap();
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_aptos_data() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use aptos_crypto::hash::CryptoHash;

        let mut aptos_wrapper = AptosWrapper::new(40, 1, 1).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let proof_assets = aptos_wrapper.get_latest_proof_account(35).unwrap();

        let intern_proof =
            SparseMerkleProof::from_bytes(&bcs::to_bytes(proof_assets.state_proof()).unwrap())
                .unwrap();
        let key = HashValue::from_slice(proof_assets.key().to_vec()).unwrap();
        let root_hash = HashValue::from_slice(proof_assets.root_hash().to_vec()).unwrap();
        let element_hash =
            HashValue::from_slice(proof_assets.state_value().clone().unwrap().hash().to_vec())
                .unwrap();

        intern_proof
            .verify_by_hash(root_hash, key, element_hash)
            .unwrap();

        assert_eq!(
            bcs::to_bytes(&root_hash).unwrap(),
            bcs::to_bytes(&proof_assets.root_hash()).unwrap()
        );
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_sparse_merkle_proof() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;

        let mut aptos_wrapper = AptosWrapper::new(40, 1, 1).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let proof_assets = aptos_wrapper.get_latest_proof_account(35).unwrap();

        let aptos_proof = proof_assets.state_proof();
        let aptos_proof_bytes = bcs::to_bytes(aptos_proof).unwrap();

        let lc_sparse_proof = SparseMerkleProof::from_bytes(&aptos_proof_bytes).unwrap();

        let lc_sparse_proof_bytes = lc_sparse_proof.to_bytes();

        assert_eq!(aptos_proof_bytes, lc_sparse_proof_bytes);
    }
}
