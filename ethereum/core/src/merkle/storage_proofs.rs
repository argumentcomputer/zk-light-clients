// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Storage Proofs
//!
//! This module is made to handle account and storage proof received from the Ethereum network. These
//! proofs should be fetch using an RPC endpoint that supports [the EIP-1186](https://eips.ethereum.org/EIPS/eip-1186).
//! The EIP-1186 is a standard that defines the format of the response of the `eth_getProof` RPC call.

use crate::crypto::hash::{keccak256_hash, HashValue};
use crate::merkle::error::MerkleError;
use crate::merkle::utils::rlp::{
    decode_list, is_empty_value, paths_match, shared_prefix_length, skip_length,
};
use crate::merkle::utils::{get_nibble, rlp::rlp_encode_account};
use crate::types::error::TypesError;
use crate::types::{Address, Bytes32};
use ethers_core::abi::AbiEncode;
use ethers_core::types::EIP1186ProofResponse;
use ethers_core::utils::rlp::encode;

/// Data structure the data received from the `eth_getProof` RPC call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EIP1186Proof {
    pub encoded_account: Vec<u8>,
    pub address: Address,
    pub storage_hash: HashValue,
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proof: Vec<StorageProof>,
}

impl TryFrom<EIP1186ProofResponse> for EIP1186Proof {
    type Error = TypesError;

    fn try_from(value: EIP1186ProofResponse) -> Result<Self, Self::Error> {
        let encoded_account = rlp_encode_account(&value);

        let account_proof = value
            .account_proof
            .into_iter()
            .map(|proof| proof.to_vec())
            .collect();
        let storage_proof = value
            .storage_proof
            .into_iter()
            .map(|storage_proof| storage_proof.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            encoded_account,
            address: value.address.to_fixed_bytes(),
            storage_hash: HashValue::new(value.storage_hash.to_fixed_bytes()),
            account_proof,
            storage_proof,
        })
    }
}

impl EIP1186Proof {
    /// Verifies the account proof and the storage proofs against the state root.
    ///
    /// # Arguments
    ///
    /// * `state_root` - The state root to verify the proofs against.
    ///
    /// # Returns
    ///
    /// A boolean indicating if the proofs are valid.
    pub fn verify(&self, state_root: &Bytes32) -> Result<bool, MerkleError> {
        if !verify_proof(
            &self.account_proof,
            state_root,
            &self.encoded_account,
            &keccak256_hash(&self.address)
                .map_err(|err| MerkleError::ProofVerification { source: err.into() })?
                .to_vec(),
        )? {
            return Ok(false);
        }

        for storage_proof in self.storage_proof.iter() {
            let key_hash = keccak256_hash(&storage_proof.key)
                .map_err(|err| MerkleError::ProofVerification { source: err.into() })?;

            if !verify_proof(
                &storage_proof.proof,
                self.storage_hash.as_ref(),
                key_hash.as_ref(),
                &storage_proof.value,
            )? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Data structure representing a storage proof.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StorageProof {
    pub key: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub value: Vec<u8>,
}

impl TryFrom<ethers_core::types::StorageProof> for StorageProof {
    type Error = TypesError;

    fn try_from(value: ethers_core::types::StorageProof) -> Result<Self, Self::Error> {
        let key = hex::decode(
            value
                .key
                .encode_hex()
                .strip_prefix("0x")
                .ok_or_else(|| TypesError::InvalidHexadecimal)?,
        )
        .map_err(|_| TypesError::InvalidHexadecimal)?;

        Ok(Self {
            key,
            proof: value
                .proof
                .into_iter()
                .map(|proof| proof.to_vec())
                .collect(),
            value: encode(&value.value).to_vec(),
        })
    }
}

/// Verifies a proof against a root hash.
///
/// # Arguments
///
/// * `proof` - The proof to verify, con.
/// * `root` - The root hash to verify the proof against.
/// * `path` - The path to the value in the tree.
/// * `value` - The value to verify.
///
/// # Returns
///
/// A boolean indicating if the proof is valid.
fn verify_proof(
    proof: &[Vec<u8>],
    root: &[u8],
    path: &[u8],
    value: &[u8],
) -> Result<bool, MerkleError> {
    let mut expected_hash = root.to_vec();
    let mut path_offset = 0;

    for (i, node) in proof.iter().enumerate() {
        if expected_hash
            != keccak256_hash(node)
                .map_err(|err| MerkleError::ProofVerification { source: err.into() })?
                .to_vec()
        {
            return Ok(false);
        }

        let node_list: Vec<Vec<u8>> = decode_list(node)
            .map_err(|err| MerkleError::ProofVerification { source: err.into() })?;

        if node_list.len() == 17 {
            if i == proof.len() - 1 {
                // exclusion proof
                let nibble = get_nibble(path, path_offset);
                let node = &node_list[nibble as usize];

                if node.is_empty()
                    && is_empty_value(value)
                        .map_err(|err| MerkleError::ProofVerification { source: err.into() })?
                {
                    return Ok(true);
                }
            } else {
                let nibble = get_nibble(path, path_offset);
                expected_hash = node_list[nibble as usize].clone();

                path_offset += 1;
            }
        } else if node_list.len() == 2 {
            if i == proof.len() - 1 {
                // exclusion proof
                if !paths_match(&node_list[0], skip_length(&node_list[0]), path, path_offset)
                    && is_empty_value(value)
                        .map_err(|err| MerkleError::ProofVerification { source: err.into() })?
                {
                    return Ok(true);
                }

                // inclusion proof
                if node_list[1] == value {
                    return Ok(paths_match(
                        &node_list[0],
                        skip_length(&node_list[0]),
                        path,
                        path_offset,
                    ));
                }
            } else {
                let node_path = &node_list[0];
                let prefix_length = shared_prefix_length(path, path_offset, node_path);
                if prefix_length < node_path.len() * 2 - skip_length(node_path) {
                    // The proof shows a divergent path, but we're not
                    // at the end of the proof, so something's wrong.
                    return Ok(false);
                }
                path_offset += prefix_length;
                expected_hash = node_list[1].clone();
            }
        } else {
            return Ok(false);
        }
    }

    Ok(false)
}
