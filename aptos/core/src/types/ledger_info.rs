//! This module defines LedgerInfo and LedgerInfoWithSignatures structs which are used to
//! represent the information about the latest committed block and the signatures of the
//! validators over the LedgerInfo.
//!
//! # Note
//!
//! In this module we define some constants that represent the offsets and lengths of the
//! fields in the serialized LedgerInfo and LedgerInfoWithSignatures structs. These constants
//! represent offset and length of the fields bytes.

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue, HASH_LENGTH};
use crate::crypto::sig::{AggregateSignature, PUB_KEY_LEN, SIG_LEN};
use crate::types::block_info::BlockInfo;
use crate::types::epoch_state::EpochState;
use crate::types::error::{TypesError, VerifyError};
use crate::types::validator::ValidatorVerifier;
use crate::types::Version;
use crate::NBR_VALIDATORS;
use bytes::{Buf, BufMut, BytesMut};
use getset::Getters;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

const ENUM_VARIANT_LEN: usize = 1;
const LEB128_VEC_SIZE_VALIDATOR_LIST: usize = 2; // For 130 validators
const NEXT_BYTE_OFFSET: usize = 1;
const EPOCH_OFFSET_INCR: usize = 8;
const ROUND_OFFSET_INCR: usize = 8;
const HASH_OFFSET_INCR: usize = 32;
const VERSION_OFFSET_INCR: usize = 8;
const TIMESTAMP_OFFSET_INCR: usize = 8;
pub const VOTING_POWER_OFFSET_INCR: usize = 8;
pub const OFFSET_VALIDATOR_LIST: usize = EPOCH_OFFSET_INCR
    + ROUND_OFFSET_INCR
    + HASH_OFFSET_INCR // id
    + HASH_OFFSET_INCR // executed state id
    + VERSION_OFFSET_INCR
    + TIMESTAMP_OFFSET_INCR
    + ENUM_VARIANT_LEN
    + EPOCH_OFFSET_INCR
    + NEXT_BYTE_OFFSET;
pub const OFFSET_LEDGER_INFO: usize = ENUM_VARIANT_LEN;
pub const LEB128_PUBKEY_LEN: usize = 1;
pub const VALIDATORS_LIST_LEN: usize = LEB128_VEC_SIZE_VALIDATOR_LIST
    + NBR_VALIDATORS
        * (HASH_OFFSET_INCR + LEB128_PUBKEY_LEN + PUB_KEY_LEN + VOTING_POWER_OFFSET_INCR);

pub const LEDGER_INFO_LEN: usize = EPOCH_OFFSET_INCR
    + ROUND_OFFSET_INCR
    + HASH_OFFSET_INCR // id
    + HASH_OFFSET_INCR // executed state id
    + VERSION_OFFSET_INCR
    + TIMESTAMP_OFFSET_INCR
    + ENUM_VARIANT_LEN
    + EPOCH_OFFSET_INCR
    + VALIDATORS_LIST_LEN
    + HASH_OFFSET_INCR; // consensus data hash

pub const OFFSET_SIGNATURE: usize = LEDGER_INFO_LEN + NEXT_BYTE_OFFSET;

const LEB128_VEC_SIZE_BITVEC: usize = 1;
const BITVEC_SIZE: usize = (NBR_VALIDATORS + 7) / 8 + 1;
pub const AGG_SIGNATURE_LEN: usize =
    LEB128_VEC_SIZE_BITVEC + BITVEC_SIZE + ENUM_VARIANT_LEN + SIG_LEN;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerInfo {
    commit_info: BlockInfo,
    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}

impl LedgerInfo {
    pub const fn new(commit_info: BlockInfo, consensus_data_hash: HashValue) -> Self {
        Self {
            commit_info,
            consensus_data_hash,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.commit_info.epoch()
    }

    pub fn next_block_epoch(&self) -> u64 {
        self.commit_info.next_block_epoch()
    }

    pub fn next_epoch_state(&self) -> Option<&EpochState> {
        self.commit_info.next_epoch_state().as_ref()
    }

    pub fn timestamp_usecs(&self) -> u64 {
        self.commit_info.timestamp_usecs()
    }

    pub fn transaction_accumulator_hash(&self) -> HashValue {
        self.commit_info.executed_state_id()
    }

    pub fn version(&self) -> Version {
        self.commit_info.version()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.commit_info.to_bytes());
        bytes.put_slice(&self.consensus_data_hash.to_vec());
        bytes.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let commit_info =
            BlockInfo::from_bytes(bytes.chunk()).map_err(|e| TypesError::DeserializationError {
                structure: String::from("LedgerInfo"),
                source: e.into(),
            })?;

        bytes.advance(bytes.len() - HASH_LENGTH); // Advance the buffer to get the hash

        let consensus_data_hash =
            HashValue::from_slice(bytes.chunk()).map_err(|e| TypesError::DeserializationError {
                structure: String::from("LedgerInfo"),
                source: e.into(),
            })?;

        Ok(Self {
            commit_info,
            consensus_data_hash,
        })
    }
}

impl CryptoHash for LedgerInfo {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"LedgerInfo"),
            vec![&bcs::to_bytes(&self).unwrap()],
        ))
    }
}

#[derive(Debug, Getters, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerInfoWithV0 {
    #[getset(get = "pub")]
    ledger_info: LedgerInfo,
    /// Aggregated BLS signature of all the validators that signed the message. The bitmask in the
    /// aggregated signature can be used to find out the individual validators signing the message
    signatures: AggregateSignature,
}

impl LedgerInfoWithV0 {
    pub fn verify_signatures(
        &self,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<(), VerifyError> {
        validator.verify_multi_signatures(self.ledger_info(), &self.signatures)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerInfoWithSignatures {
    V0(LedgerInfoWithV0),
}

// This deref polymorphism anti-pattern is in the upstream code (!)
impl Deref for LedgerInfoWithSignatures {
    type Target = LedgerInfoWithV0;

    fn deref(&self) -> &LedgerInfoWithV0 {
        match &self {
            LedgerInfoWithSignatures::V0(ledger) => ledger,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::hash::{prefixed_sha3, HASH_LENGTH};
    use tiny_keccak::{Hasher, Sha3};

    #[test]
    fn test_hash() {
        let ledger_info = LedgerInfo {
            commit_info: BlockInfo::default(),
            consensus_data_hash: HashValue::default(),
        };

        let expected = {
            let mut digest = Sha3::v256();
            digest.update(&prefixed_sha3(b"LedgerInfo"));
            digest.update(&bcs::to_bytes(&ledger_info).unwrap());
            let mut hasher_bytes = [0u8; HASH_LENGTH];
            digest.finalize(&mut hasher_bytes);
            hasher_bytes
        };

        let actual = ledger_info.hash();

        assert_eq!(expected, actual.hash());
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_ledger_info() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let ledger_info_bytes = &aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .skip(OFFSET_LEDGER_INFO)
            .take(LEDGER_INFO_LEN)
            .copied()
            .collect::<Vec<u8>>();

        let ledger_info_deserialized = LedgerInfo::from_bytes(ledger_info_bytes).unwrap();
        let ledger_info_serialized = ledger_info_deserialized.to_bytes();

        assert_eq!(ledger_info_bytes, &ledger_info_serialized);
    }
}
