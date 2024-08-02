// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Storage Proofs
//!
//! This module is made to handle account and storage proof received from the Ethereum network. These
//! proofs should be fetch using an RPC endpoint that supports [the EIP-1186](https://eips.ethereum.org/EIPS/eip-1186).
//! The EIP-1186 is a standard that defines the format of the response of the `eth_getProof` RPC call.
//!
//! This module only handles inclusion proofs from the EIP1186.

use crate::crypto::hash::{keccak256_hash, HashValue, HASH_LENGTH};
use crate::deserialization_error;
use crate::merkle::error::MerkleError;
use crate::merkle::utils::rlp::{decode_list, paths_match, shared_prefix_length, skip_length};
use crate::merkle::utils::{get_nibble, rlp::rlp_encode_account};
use crate::types::error::TypesError;
use crate::types::utils::{
    extract_fixed_bytes, extract_u32, ssz_decode_list_bytes, ssz_encode_list_bytes,
    OFFSET_BYTE_LENGTH,
};
use crate::types::{Address, Bytes32, ADDRESS_BYTES_LEN};
use ethers_core::abi::AbiEncode;
use ethers_core::types::EIP1186ProofResponse;
use ethers_core::utils::rlp::encode;
use getset::Getters;

/// Bse byte length for the SSZ serialized `EIP1186Proof`.
pub const EIP1186_PROOF_BASE_BYTE_LENGTH: usize =
    OFFSET_BYTE_LENGTH * 3 + ADDRESS_BYTES_LEN + HASH_LENGTH;

/// Length of a branch node in an Ethereum Patricia Merkle tree.
///
/// From [the Ethereum documentation](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/).
const BRANCH_NODE_LENGTH: usize = 17;

/// Length of a leaf or any extension node.
///
/// From [the Ethereum documentation](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/).
const LEAF_EXTENSION_NODE_LENGTH: usize = 2;

/// Data structure the data received from the `eth_getProof` RPC call.
#[derive(Debug, Clone, PartialEq, Eq, Getters)]
#[getset(get = "pub")]
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
            .map(StorageProof::try_from)
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
        let address_hash = keccak256_hash(&self.address)
            .map_err(|err| MerkleError::ProofVerification { source: err.into() })?;
        if !verify_proof(
            &self.account_proof,
            state_root,
            &self.encoded_account,
            address_hash.as_ref(),
        )? {
            return Ok(false);
        }

        for storage_proof in &self.storage_proof {
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

    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut final_bytes = vec![];

        // Serialize encoded account
        final_bytes.extend_from_slice(&(EIP1186_PROOF_BASE_BYTE_LENGTH as u32).to_le_bytes());
        let encoded_account_bytes = &self.encoded_account;

        // Serialize address
        final_bytes.extend_from_slice(&self.address);

        // Serialize storage hash
        final_bytes.extend_from_slice(self.storage_hash.as_ref());

        // Account proof serialization
        let account_proof_offset = EIP1186_PROOF_BASE_BYTE_LENGTH + encoded_account_bytes.len();
        final_bytes.extend_from_slice(&(account_proof_offset as u32).to_le_bytes());

        let account_proof_bytes = ssz_encode_list_bytes(&self.account_proof);

        // Storage proof serialization
        let storage_proof_offset = account_proof_offset + account_proof_bytes.len();
        final_bytes.extend_from_slice(&(storage_proof_offset as u32).to_le_bytes());

        let proof_as_list_bytes = self
            .storage_proof
            .iter()
            .map(|proof| proof.to_ssz_bytes())
            .collect::<Vec<_>>();
        let storage_proof_bytes = ssz_encode_list_bytes(&proof_as_list_bytes);

        // Extend final bytes
        final_bytes.extend_from_slice(encoded_account_bytes);
        final_bytes.extend_from_slice(&account_proof_bytes);
        final_bytes.extend_from_slice(&storage_proof_bytes);

        final_bytes
    }

    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let cursor = 0;

        // Retrieve encoded account offset
        let (cursor, account_offset) = extract_u32("EIP1186Proof", bytes, cursor)?;

        // Retrieve address bytes
        let (cursor, address) =
            extract_fixed_bytes::<ADDRESS_BYTES_LEN>("EIP1186Proof", bytes, cursor)?;

        // Retrieve storage hash bytes
        let (cursor, storage_hash) =
            extract_fixed_bytes::<HASH_LENGTH>("EIP1186Proof", bytes, cursor)?;

        // Retrieve account proof offset
        let (cursor, account_proof_offset) = extract_u32("EIP1186Proof", bytes, cursor)?;

        // Retrieve storage proof offset
        let (cursor, storage_proof_offset) = extract_u32("EIP1186Proof", bytes, cursor)?;

        // Retrieve encoded account
        if cursor != account_offset as usize {
            return Err(deserialization_error!(
                "EIP1186Proof",
                "Invalid offset for encoded account"
            ));
        }
        let encoded_account = bytes
            .get(cursor..account_proof_offset as usize)
            .ok_or_else(|| TypesError::OutOfBounds {
                structure: "EIP1186Proof".into(),
                offset: account_proof_offset as usize,
                length: bytes.len(),
            })?
            .to_vec();

        // Retrieve account proof
        let cursor = cursor + encoded_account.len();
        if cursor != account_proof_offset as usize {
            return Err(deserialization_error!(
                "EIP1186Proof",
                "Invalid offset for account proof"
            ));
        }
        let account_proof_bytes = bytes
            .get(cursor..storage_proof_offset as usize)
            .ok_or_else(|| TypesError::OutOfBounds {
                structure: "EIP1186Proof".into(),
                offset: storage_proof_offset as usize,
                length: bytes.len(),
            })?;
        let account_proof = ssz_decode_list_bytes(account_proof_bytes)?;

        // Retrieve storage proof
        let cursor = cursor + account_proof_bytes.len();
        if cursor != storage_proof_offset as usize {
            return Err(deserialization_error!(
                "EIP1186Proof",
                "Invalid offset for storage proof"
            ));
        }
        let storage_proof_bytes = bytes.get(cursor..).ok_or_else(|| TypesError::OutOfBounds {
            structure: "EIP1186Proof".into(),
            offset: cursor,
            length: bytes.len(),
        })?;
        let storage_proof = ssz_decode_list_bytes(storage_proof_bytes)?
            .iter()
            .map(|v| StorageProof::from_ssz_bytes(v))
            .collect::<Result<Vec<StorageProof>, _>>()?;

        Ok(Self {
            encoded_account,
            address,
            storage_hash: HashValue::new(storage_hash),
            account_proof,
            storage_proof,
        })
    }
}

/// Offset for the key in a SSZ serialized `StorageProof`.
pub const STORAGE_PROOF_KEY_OFFSET: usize = OFFSET_BYTE_LENGTH * 3;

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
        let key = hex::decode(value.key.encode_hex().strip_prefix("0x").unwrap_or(""))
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

impl StorageProof {
    /// SSZ serialization method for the `StorageProof` data structure.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `StorageProof` data structure.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut final_bytes = vec![];

        // Key serialization
        final_bytes.extend_from_slice(&(STORAGE_PROOF_KEY_OFFSET as u32).to_le_bytes());
        let key_bytes = &self.key;

        // Proof serialization
        let proof_offset = STORAGE_PROOF_KEY_OFFSET + key_bytes.len();
        final_bytes.extend_from_slice(&(proof_offset as u32).to_le_bytes());

        let proof_bytes = ssz_encode_list_bytes(&self.proof);

        // Value serialization
        let value_offset = proof_offset + proof_bytes.len();
        final_bytes.extend_from_slice(&(value_offset as u32).to_le_bytes());

        // Extend with all values
        final_bytes.extend_from_slice(key_bytes);
        final_bytes.extend_from_slice(&proof_bytes);
        final_bytes.extend_from_slice(&self.value);

        final_bytes
    }

    /// SSZ deserialization method for the `StorageProof` data structure.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ formatted bytes to deserialize the `StorageProof` data structure from.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `StorageProof` data structure or a `TypesError`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let cursor = 0;
        let (cursor, key_offset) = extract_u32("StorageProof", bytes, cursor)?;
        let (cursor, proof_offset) = extract_u32("StorageProof", bytes, cursor)?;
        let (cursor, value_offset) = extract_u32("StorageProof", bytes, cursor)?;

        // Retrieve key
        if cursor != key_offset as usize {
            return Err(deserialization_error!(
                "StorageProof",
                "Invalid offset for key"
            ));
        }

        let key = bytes
            .get(cursor..proof_offset as usize)
            .ok_or_else(|| TypesError::OutOfBounds {
                structure: "StorageProof".into(),
                offset: proof_offset as usize,
                length: bytes.len(),
            })?
            .to_vec();

        // Retrieve proof
        let cursor = cursor + key.len();
        if cursor != proof_offset as usize {
            return Err(deserialization_error!(
                "StorageProof",
                "Invalid offset for proof"
            ));
        }

        let proof_bytes =
            bytes
                .get(cursor..value_offset as usize)
                .ok_or_else(|| TypesError::OutOfBounds {
                    structure: "StorageProof".into(),
                    offset: value_offset as usize,
                    length: bytes.len(),
                })?;

        let proof = ssz_decode_list_bytes(proof_bytes)?;

        // Retrieve value
        let cursor = cursor + proof_bytes.len();
        if cursor != value_offset as usize {
            return Err(deserialization_error!(
                "StorageProof",
                "Invalid offset for value"
            ));
        }

        let value = bytes
            .get(cursor..)
            .ok_or_else(|| TypesError::OutOfBounds {
                structure: "StorageProof".into(),
                offset: cursor,
                length: bytes.len(),
            })?
            .to_vec();

        Ok(Self { key, proof, value })
    }
}

/// Verifies a proof against a root hash.
///
/// # Arguments
///
/// * `proof` - The proof to verify.
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

        let node_list = decode_list(node)
            .map_err(|err| MerkleError::ProofVerification { source: err.into() })?;

        if node_list.len() == BRANCH_NODE_LENGTH {
            let nibble = get_nibble(path, path_offset);
            expected_hash = node_list[nibble as usize].clone();
            path_offset += 1;
        } else if node_list.len() == LEAF_EXTENSION_NODE_LENGTH {
            if i == proof.len() - 1 && node_list[1] == value {
                return Ok(paths_match(
                    &node_list[0],
                    skip_length(&node_list[0]),
                    path,
                    path_offset,
                ));
            } else {
                let node_path = &node_list[0];
                let prefix_length = shared_prefix_length(path, path_offset, node_path);
                if prefix_length < node_path.len() * 2 - skip_length(node_path) {
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

#[cfg(test)]
mod test {
    use crate::merkle::storage_proofs::{EIP1186Proof, StorageProof};
    use serde::{Deserialize, Serialize};
    use ssz::Encode;
    use ssz_derive::{Decode, Encode};
    use ssz_types::typenum::{U10, U20, U3, U32, U6, U8, U9};
    use ssz_types::{FixedVector, VariableList};

    #[derive(Debug, Clone, PartialEq, Encode, Decode, Serialize, Deserialize)]
    struct EIP1186ProofTest {
        encoded_account: VariableList<u8, U8>,
        address: FixedVector<u8, U20>,
        storage_hash: FixedVector<u8, U32>,
        account_proof: VariableList<VariableList<u8, U10>, U3>,
        storage_proof: VariableList<StorageProofTest, U6>,
    }

    #[derive(Debug, Clone, PartialEq, Encode, Decode, Serialize, Deserialize)]
    struct StorageProofTest {
        key: VariableList<u8, U8>,
        proof: VariableList<VariableList<u8, U10>, U3>,
        value: VariableList<u8, U9>,
    }

    fn assert_storage_proof_equality(
        storage_proof: &StorageProof,
        storage_proof_test: &StorageProofTest,
    ) {
        assert_eq!(storage_proof.key, storage_proof_test.key.to_vec());
        assert_eq!(
            storage_proof.proof.len(),
            storage_proof_test.proof.to_vec().len()
        );
        for (i, proof) in storage_proof.proof.iter().enumerate() {
            assert_eq!(proof, &storage_proof_test.proof.to_vec()[i].to_vec());
        }
        assert_eq!(storage_proof.value, storage_proof_test.value.to_vec());

        let storage_proof_bytes = storage_proof.to_ssz_bytes();
        let serialized_storage_proof_test = storage_proof_test.as_ssz_bytes();

        assert_eq!(storage_proof_bytes, serialized_storage_proof_test);
    }

    #[test]
    fn test_ssz_serde_storage_proof() {
        let storage_proof_test = StorageProofTest {
            key: VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            proof: VariableList::from(vec![
                VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                VariableList::from(vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
                VariableList::from(vec![21, 22, 23, 24, 25, 26, 27, 28, 29, 30]),
            ]),
            value: VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]),
        };

        let serialized_storage_proof_test = storage_proof_test.as_ssz_bytes();

        let storage_proof = StorageProof::from_ssz_bytes(&serialized_storage_proof_test).unwrap();

        assert_storage_proof_equality(&storage_proof, &storage_proof_test);
    }

    #[test]
    fn test_ssz_serde_eip1186_response() {
        let storage_proof_test = StorageProofTest {
            key: VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            proof: VariableList::from(vec![
                VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                VariableList::from(vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
                VariableList::from(vec![21, 22, 23, 24, 25, 26, 27, 28, 29, 30]),
            ]),
            value: VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]),
        };

        let eip1186_proof_test = EIP1186ProofTest {
            encoded_account: VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            address: FixedVector::from(vec![1; 20]),
            storage_hash: FixedVector::from(vec![1; 32]),
            account_proof: VariableList::from(vec![
                VariableList::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                VariableList::from(vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
                VariableList::from(vec![21, 22, 23, 24, 25, 26, 27, 28, 29, 30]),
            ]),
            storage_proof: VariableList::from(vec![storage_proof_test]),
        };

        let serialized_eip1186_proof_test = eip1186_proof_test.as_ssz_bytes();

        let eip1186_proof = EIP1186Proof::from_ssz_bytes(&serialized_eip1186_proof_test).unwrap();

        assert_eq!(
            eip1186_proof.encoded_account,
            eip1186_proof_test.encoded_account.to_vec()
        );
        assert_eq!(
            eip1186_proof.address.to_vec(),
            eip1186_proof_test.address.to_vec()
        );
        assert_eq!(
            eip1186_proof.storage_hash.to_vec(),
            eip1186_proof_test.storage_hash.to_vec()
        );
        assert_eq!(
            eip1186_proof.account_proof.len(),
            eip1186_proof_test.account_proof.to_vec().len()
        );
        for (i, proof) in eip1186_proof.account_proof.iter().enumerate() {
            assert_eq!(
                proof,
                &eip1186_proof_test.account_proof.to_vec()[i].to_vec()
            );
        }
        assert_eq!(
            eip1186_proof.storage_proof.len(),
            eip1186_proof_test.storage_proof.to_vec().len()
        );

        for (i, proof) in eip1186_proof.storage_proof.iter().enumerate() {
            assert_storage_proof_equality(proof, &eip1186_proof_test.storage_proof.to_vec()[i]);
        }

        let eip1186_proof_bytes = eip1186_proof.to_ssz_bytes();

        assert_eq!(eip1186_proof_bytes, serialized_eip1186_proof_test);
    }
}
