// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::HashValue;
use crate::merkle::node::SparseMerkleLeafNode;
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
    /// # Note
    /// For now, the `N` parameter needs to represent the number of siblings to use in the proof verification multiplied by 3 in
    /// as each sibling inputs are 3 field elements.
    #[allow(dead_code)]
    pub fn verify_by_hash<const N: usize>(
        &self,
        _expected_root_hash: HashValue,
        element_key: HashValue,
        element_hash: HashValue,
    ) -> anyhow::Result<()> {
        ensure!(
            self.siblings.len() <= 256,
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

        Ok(())
    }
}
