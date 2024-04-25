use bytes::{Buf, BufMut, BytesMut};
// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue, HASH_LENGTH};
use crate::types::error::TypesError;
use getset::CopyGetters;
use serde::{Deserialize, Serialize};

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
        let key = HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
            TypesError::DeserializationError {
                structure: String::from("SparseMerkleLeafNode"),
                source: "Not enough data for key".into(),
            }
        })?)
        .map_err(|e| TypesError::DeserializationError {
            structure: String::from("SparseMerkleLeafNode"),
            source: e.into(),
        })?;
        buf.advance(HASH_LENGTH);
        let value_hash =
            HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                TypesError::DeserializationError {
                    structure: String::from("SparseMerkleLeafNode"),
                    source: "Not enough data for value_hash".into(),
                }
            })?)
            .map_err(|e| TypesError::DeserializationError {
                structure: String::from("SparseMerkleLeafNode"),
                source: e.into(),
            })?;
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

pub struct SparseMerkleInternalNode {
    left_child: HashValue,
    right_child: HashValue,
}

impl SparseMerkleInternalNode {
    pub const fn new(left_child: HashValue, right_child: HashValue) -> Self {
        Self {
            left_child,
            right_child,
        }
    }
}

impl CryptoHash for SparseMerkleInternalNode {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"SparseMerkleInternal"),
            vec![&self.left_child.hash(), &self.right_child.hash()],
        ))
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "aptos")]
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

    #[cfg(feature = "aptos")]
    #[test]
    fn test_sparse_merkle_internal_node_hash() {
        use crate::crypto::hash::CryptoHash as LcCryptoHash;
        use crate::crypto::hash::HashValue as LcHashValue;
        use crate::merkle::node::SparseMerkleInternalNode as LcSparseMerkleInternalNode;

        use aptos_crypto::hash::CryptoHash as AptosCryptoHash;
        use aptos_crypto::HashValue as AptosHashValue;
        use aptos_types::proof::SparseMerkleInternalNode as AptosSparseMerkleInternalNode;

        let key_slice = [10; 32];
        let value_hash_slice = [15; 32];

        let key_lc = LcHashValue::from_slice(key_slice).unwrap();
        let value_hash_lc = LcHashValue::from_slice(value_hash_slice).unwrap();

        let lc_hash = LcCryptoHash::hash(&LcSparseMerkleInternalNode::new(key_lc, value_hash_lc));

        let key_aptos = AptosHashValue::new(key_slice);
        let value_hash_aptos = AptosHashValue::new(value_hash_slice);

        let aptos_hash = AptosCryptoHash::hash(&AptosSparseMerkleInternalNode::new(
            key_aptos,
            value_hash_aptos,
        ));

        assert_eq!(lc_hash.to_vec(), aptos_hash.to_vec());
    }

    #[cfg(feature = "aptos")]
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
