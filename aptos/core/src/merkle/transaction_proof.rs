//! # Transaction Proof Module
//!
//! This module provides the structures and functions
//! necessary for handling Transaction Accumulator Proofs
//! from the Aptos chain.
//!
//! ## Usage
//!
//! The `TransactionAccumulatorProof` structure is
//! used to authenticate whether a given transaction exists
//! in the  Aptos state or not. It contains a list of sibling nodes,
//! ordered from the bottom level to the root level of the Merkle Tree.

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{CryptoHash, HashValue, HASH_LENGTH};
use crate::merkle::node::MerkleInternalNode;
use crate::merkle::node::TransactionAccumulatorHasher;
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::{read_leb128, write_leb128};
use anyhow::{ensure, Result};
use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};

pub const MAX_ACCUMULATOR_PROOF_DEPTH: usize = 63;

/// A proof that can be used authenticate an element in an
/// accumulator given trusted root hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAccumulatorProof {
    /// All siblings in this proof, including the default ones. Siblings
    /// are ordered from the bottom level to the root level.
    siblings: Vec<HashValue>,
}

impl TransactionAccumulatorProof {
    /// Verifies an element whose hash is `element_hash` and version is `element_version` exists in
    /// the accumulator whose root hash is `expected_root_hash` using the provided proof.
    ///
    /// # Arguments
    ///
    /// * `expected_root_hash: HashValue` - The expected root hash of the Transaction Accumulator.
    /// * `element_hash: HashValue` - The hash of the element to verify.
    /// * `element_index: u64` - The index of the element to verify.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the element exists in the Transaction Accumulator and the proof is valid, and `Err` otherwise.
    pub fn verify(
        &self,
        expected_root_hash: HashValue,
        element_hash: HashValue,
        element_index: u64,
    ) -> Result<()> {
        ensure!(
            self.siblings.len() <= MAX_ACCUMULATOR_PROOF_DEPTH,
            "Accumulator proof has more than {} ({}) siblings.",
            MAX_ACCUMULATOR_PROOF_DEPTH,
            self.siblings.len()
        );

        let actual_root_hash = self
            .siblings
            .iter()
            .fold(
                (element_hash, element_index),
                // `index` denotes the index of the ancestor of the element at the current level.
                |(hash, index), sibling_hash| {
                    (
                        if index % 2 == 0 {
                            // the current node is a left child.
                            MerkleInternalNode::<TransactionAccumulatorHasher>::new(
                                hash,
                                *sibling_hash,
                            )
                            .hash()
                        } else {
                            // the current node is a right child.
                            MerkleInternalNode::<TransactionAccumulatorHasher>::new(
                                *sibling_hash,
                                hash,
                            )
                            .hash()
                        },
                        // The index of the parent at its level.
                        index / 2,
                    )
                },
            )
            .0;
        ensure!(
            actual_root_hash == expected_root_hash,
            "{}: Root hashes do not match.",
            "AccumulatorProof",
        );

        Ok(())
    }

    /// Converts the `TransactionAccumulatorProof` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `TransactionAccumulatorProof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&write_leb128(self.siblings.len() as u64));
        for sibling in &self.siblings {
            bytes.put_slice(sibling.as_ref());
        }
        bytes.to_vec()
    }

    /// Creates a `TransactionAccumulatorProof` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `TransactionAccumulatorProof`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `TransactionAccumulatorProof` could be successfully created, and `Err` otherwise.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, TypesError> {
        let mut buf = BytesMut::from(bytes);
        let (len, read_bytes) = read_leb128(&buf).map_err(|_| {
            serde_error!("TransactionAccumulatorProof", "Not enough data for length")
        })?;
        buf.advance(read_bytes);
        let mut siblings = Vec::with_capacity(len as usize);
        for _ in 0..len {
            if buf.remaining() < HASH_LENGTH {
                return Err(serde_error!(
                    "TransactionAccumulatorProof",
                    "Not enough bytes to read HashValue"
                ));
            }
            let mut hash_value = [0u8; HASH_LENGTH];
            buf.copy_to_slice(&mut hash_value);
            siblings.push(
                HashValue::from_slice(hash_value)
                    .map_err(|e| serde_error!("TransactionAccumulatorProof", e))?,
            );
        }

        if buf.remaining() != 0 {
            return Err(serde_error!(
                "TransactionAccumulatorProof",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self { siblings })
    }
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    #[test]
    fn test_bytes_conversion_transaction_accumulator_proof() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::merkle::transaction_proof::TransactionAccumulatorProof;

        let mut aptos_wrapper = AptosWrapper::new(40, 1, 1).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let proof_assets = aptos_wrapper.get_latest_proof_account(35).unwrap();

        let aptos_proof = proof_assets.transaction_proof();
        let aptos_proof_bytes = bcs::to_bytes(aptos_proof).unwrap();

        let lc_sparse_proof = TransactionAccumulatorProof::from_bytes(&aptos_proof_bytes).unwrap();

        let lc_sparse_proof_bytes = lc_sparse_proof.to_bytes();

        assert_eq!(aptos_proof_bytes, lc_sparse_proof_bytes);
    }

    #[test]
    fn test_transaction_accumulator() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::crypto::hash::HashValue;
        use crate::merkle::transaction_proof::TransactionAccumulatorProof;
        use aptos_crypto::hash::CryptoHash;

        let mut aptos_wrapper = AptosWrapper::new(40, 1, 1).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let proof_assets = aptos_wrapper.get_latest_proof_account(35).unwrap();

        let latest_li = aptos_wrapper.get_latest_li().unwrap();

        let expected_root_hash = HashValue::from_slice(
            latest_li
                .ledger_info()
                .transaction_accumulator_hash()
                .as_ref(),
        )
        .unwrap();
        let element_hash =
            HashValue::from_slice(proof_assets.transaction().hash().as_ref()).unwrap();
        let element_index = *proof_assets.transaction_version();
        let proof = TransactionAccumulatorProof::from_bytes(
            &bcs::to_bytes(proof_assets.transaction_proof()).unwrap(),
        )
        .unwrap();

        proof
            .verify(expected_root_hash, element_hash, element_index)
            .unwrap()
    }
}
