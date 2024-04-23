// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
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
}
