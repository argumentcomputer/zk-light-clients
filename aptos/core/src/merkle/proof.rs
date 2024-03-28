// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{CryptoHash, HashValue, HASH_LENGTH};
use crate::merkle::node::{SparseMerkleInternalNode, SparseMerkleLeafNode};
use anyhow::ensure;
use getset::Getters;
use serde::{Deserialize, Serialize};

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
    /// Verifies an element whose key is `element_key` and value is authenticated by `element_hash` exists in the Sparse
    /// Merkle Tree using the provided proof.
    #[allow(dead_code)]
    pub fn verify_by_hash(
        &self,
        expected_root_hash: HashValue,
        element_key: HashValue,
        element_hash: HashValue,
    ) -> anyhow::Result<HashValue> {
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
            "Value hashes do not match for key {:x}. Value hash in proof: {:x}. \
                     Expected value hash: {:x}. ",
            element_key,
            leaf.value_hash(),
            element_hash
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
            .fold(leaf.hash(), |acc_hash, (sibling_hash, bit)| {
                if bit {
                    SparseMerkleInternalNode::new(*sibling_hash, acc_hash).hash()
                } else {
                    SparseMerkleInternalNode::new(acc_hash, *sibling_hash).hash()
                }
            });

        ensure!(
            reconstructed_root == expected_root_hash,
            "Root hash mismatch. Expected root hash: {:x}. Computed root hash: {:x}",
            expected_root_hash,
            reconstructed_root
        );

        Ok(reconstructed_root)
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::hash::CryptoHash;
    use crate::crypto::hash::{hash_data, HashValue, HASH_LENGTH};
    use crate::merkle::node::{SparseMerkleInternalNode, SparseMerkleLeafNode};
    use crate::merkle::proof::SparseMerkleProof;

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
                    SparseMerkleInternalNode::new(*sibling_hash, acc_hash).hash()
                } else {
                    SparseMerkleInternalNode::new(acc_hash, *sibling_hash).hash()
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

        let mut aptos_wrapper = AptosWrapper::new(40, 1);
        aptos_wrapper.generate_traffic();

        let proof_assets = aptos_wrapper.get_latest_proof_account(35).unwrap();

        let intern_proof: SparseMerkleProof =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.state_proof()).unwrap()).unwrap();
        let key: HashValue = bcs::from_bytes(&bcs::to_bytes(proof_assets.key()).unwrap()).unwrap();
        let root_hash: HashValue =
            bcs::from_bytes(&bcs::to_bytes(proof_assets.root_hash()).unwrap()).unwrap();
        let element_hash: HashValue = bcs::from_bytes(
            &bcs::to_bytes(&proof_assets.state_value().clone().unwrap().hash()).unwrap(),
        )
        .unwrap();

        intern_proof
            .verify_by_hash(root_hash, key, element_hash)
            .unwrap();
    }
}
