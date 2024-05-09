//! # Merkle Node Module
//!
//! This module provides the necessary structures and traits for
//! handling Merkle nodes in the context of Sparse Merkle Proofs
//! and Transaction Accumulator Proofs.
//!
//! ## Design
//!
//! The `MerkleInternalNode` structure and `NodeHasher` trait
//! were designed to provide a unified way to handle internal nodes
//! in both Sparse Merkle Proofs and Transaction Accumulator Proofs.
//! While the behavior of internal nodes is essentially the same in
//! both contexts, the difference lies in the prefix they provide for hashing.
//!
//! The `NodeHasher` trait allows for a dynamic way to provide
//! the prefix depending on the context, while relying on the same
//! hash method. This design provides a level of abstraction that
//! simplifies the handling of different types of proofs.
//!
//! In most cases, the prefix added while hashing an object is its name
//! as described [here](https://docs.rs/aptos-crypto-derive-link/latest/aptos_crypto_derive_link/).
//! `NodeHasher` circumvents around that as it is precisely an implementation
//!  that makes the prefix dynamic for Internal Merkle Nodes.
//!
//! The `SparseMerkleInternalHasher` and `TransactionAccumulatorHasher`
//! structures implement the `NodeHasher` trait, each providing a
//! different prefix for hashing.
//!
//! ## Usage
//!
//! The `SparseMerkleLeafNode` structure provides methods for
//! creating a new node (`new`), converting the node to bytes (`to_bytes`),
//! and creating a node from bytes (`from_bytes`).
//!
//! The `MerkleInternalNode` structure provides a method for creating
//! a new node (`new`), and implements the `CryptoHash` trait,
//! which provides a method for hashing the node (`hash`).
//!
//! The `NodeHasher` trait provides a method for hashing (`hash`),
//! which takes in the left and right child nodes and returns a `HashValue`.
//!
//! The `SparseMerkleInternalHasher` and `TransactionAccumulatorHasher`
//! structures implement the `NodeHasher` trait, each providing
//! a different prefix for hashing.
//!

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue, HASH_LENGTH};
use crate::serde_error;
use crate::types::error::TypesError;
use bytes::{Buf, BufMut, BytesMut};
use getset::CopyGetters;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, CopyGetters)]
pub struct SparseMerkleLeafNode {
    #[getset(get_copy = "pub")]
    key: HashValue,
    #[getset(get_copy = "pub")]
    value_hash: HashValue,
}

impl SparseMerkleLeafNode {
    pub const fn new(key: HashValue, value_hash: HashValue) -> Self {
        Self { key, value_hash }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(self.key.to_vec().as_slice());
        bytes.put_slice(self.value_hash.to_vec().as_slice());
        bytes.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let mut buf = bytes;

        let key = HashValue::from_slice(
            buf.chunk()
                .get(..HASH_LENGTH)
                .ok_or_else(|| serde_error!("SparseMerkleLeafNode", "Not enough data for key"))?,
        )
        .map_err(|e| serde_error!("SparseMerkleLeafNode", e))?;
        buf.advance(HASH_LENGTH);

        let value_hash =
            HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                serde_error!("SparseMerkleLeafNode", "Not enough data for value_hash")
            })?)
            .map_err(|e| serde_error!("SparseMerkleLeafNode", e))?;
        buf.advance(HASH_LENGTH);

        if buf.remaining() != 0 {
            return Err(serde_error!(
                "SparseMerkleLeafNode",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self { key, value_hash })
    }
}

impl CryptoHash for SparseMerkleLeafNode {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"SparseMerkleLeafNode"),
            vec![&self.key.hash(), &self.value_hash.hash()],
        ))
    }
}

pub struct MerkleInternalNode<H: NodeHasher> {
    left_child: HashValue,
    right_child: HashValue,
    _p: PhantomData<H>,
}

impl<H: NodeHasher> MerkleInternalNode<H> {
    pub const fn new(left_child: HashValue, right_child: HashValue) -> Self {
        Self {
            left_child,
            right_child,
            _p: PhantomData,
        }
    }
}

impl<H: NodeHasher + Default> CryptoHash for MerkleInternalNode<H> {
    fn hash(&self) -> HashValue {
        H::default().hash(&self.left_child, &self.right_child)
    }
}

/// Trait used to implement generic hasher over `MerkleInternalNode` for
/// its hash method.
pub trait NodeHasher {
    fn prefix(&self) -> &'static str;
    fn hash(&self, left_child: &HashValue, right_child: &HashValue) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(self.prefix().as_bytes()),
            vec![&left_child.hash(), &right_child.hash()],
        ))
    }
}

/// Structure representing the hasher  for node accumulator in
/// order to prove  an account inclusion in the state.
#[derive(Clone, Debug, Default)]
pub struct SparseMerkleInternalHasher {}

impl NodeHasher for SparseMerkleInternalHasher {
    fn prefix(&self) -> &'static str {
        "SparseMerkleInternal"
    }
}

/// Structure representing the hasher for  transaction accumulator
/// in order to prove its inclusion in a `LedgerInfoWithSignature`.
#[derive(Clone, Debug, Default)]
pub struct TransactionAccumulatorHasher {}

impl NodeHasher for TransactionAccumulatorHasher {
    fn prefix(&self) -> &'static str {
        "TransactionAccumulator"
    }
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    #[test]
    fn test_sparse_merkle_leaf_node_hash() {
        use crate::crypto::hash::CryptoHash as LcCryptoHash;
        use crate::crypto::hash::HashValue as LcHashValue;
        use crate::merkle::node::SparseMerkleLeafNode as LcSparseMerkleLeafNode;

        use aptos_crypto::hash::CryptoHash as AptosCryptoHash;
        use aptos_crypto::HashValue as AptosHashValue;
        use aptos_types::proof::SparseMerkleLeafNode as AptosSparseMerkleLeafNode;

        let key_slice = [10; 32];
        let value_hash_slice = [15; 32];

        let key_lc = LcHashValue::from_slice(key_slice).unwrap();
        let value_hash_lc = LcHashValue::from_slice(value_hash_slice).unwrap();

        let lc_hash = LcCryptoHash::hash(&LcSparseMerkleLeafNode::new(key_lc, value_hash_lc));

        let key_aptos = AptosHashValue::new(key_slice);
        let value_hash_aptos = AptosHashValue::new(value_hash_slice);

        let aptos_hash =
            AptosCryptoHash::hash(&AptosSparseMerkleLeafNode::new(key_aptos, value_hash_aptos));

        assert_eq!(lc_hash.to_vec(), aptos_hash.to_vec());
    }

    #[test]
    fn test_sparse_merkle_internal_node_hash() {
        use crate::crypto::hash::CryptoHash as LcCryptoHash;
        use crate::crypto::hash::HashValue as LcHashValue;
        use crate::merkle::node::MerkleInternalNode as LcSparseMerkleInternalNode;
        use crate::merkle::node::SparseMerkleInternalHasher;

        use aptos_crypto::hash::CryptoHash as AptosCryptoHash;
        use aptos_crypto::HashValue as AptosHashValue;
        use aptos_types::proof::SparseMerkleInternalNode as AptosSparseMerkleInternalNode;

        let key_slice = [10; 32];
        let value_hash_slice = [15; 32];

        let key_lc = LcHashValue::from_slice(key_slice).unwrap();
        let value_hash_lc = LcHashValue::from_slice(value_hash_slice).unwrap();

        let lc_hash = LcCryptoHash::hash(
            &LcSparseMerkleInternalNode::<SparseMerkleInternalHasher>::new(key_lc, value_hash_lc),
        );

        let key_aptos = AptosHashValue::new(key_slice);
        let value_hash_aptos = AptosHashValue::new(value_hash_slice);

        let aptos_hash = AptosCryptoHash::hash(&AptosSparseMerkleInternalNode::new(
            key_aptos,
            value_hash_aptos,
        ));

        assert_eq!(lc_hash.to_vec(), aptos_hash.to_vec());
    }

    #[test]
    fn test_bytes_conversion_sparse_merkle_leaf_node() {
        use crate::crypto::hash::HashValue;
        use crate::merkle::node::SparseMerkleLeafNode;

        use aptos_crypto::HashValue as AptosHashValue;
        use aptos_types::proof::SparseMerkleLeafNode as AptosSparseMerkleLeafNode;

        let key_slice = [10; 32];
        let value_hash_slice = [15; 32];

        let lc_node = SparseMerkleLeafNode::new(
            HashValue::from_slice(key_slice).unwrap(),
            HashValue::from_slice(value_hash_slice).unwrap(),
        );
        let lc_bytes = lc_node.to_bytes();

        let aptos_node = AptosSparseMerkleLeafNode::new(
            AptosHashValue::from_slice(key_slice).unwrap(),
            AptosHashValue::from_slice(value_hash_slice).unwrap(),
        );
        let aptos_bytes = bcs::to_bytes(&aptos_node).unwrap();

        assert_eq!(lc_bytes, aptos_bytes);

        let lc_node_deserialized = SparseMerkleLeafNode::from_bytes(&aptos_bytes).unwrap();
        let aptos_node_deserialized: AptosSparseMerkleLeafNode =
            bcs::from_bytes(&lc_bytes).unwrap();

        assert_eq!(lc_node, lc_node_deserialized);
        assert_eq!(aptos_node, aptos_node_deserialized);
    }
}
