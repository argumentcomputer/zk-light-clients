// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
use crate::crypto::sig::AggregateSignature;
use crate::types::block_info::BlockInfo;
use crate::types::epoch_state::EpochState;
use crate::types::error::VerifyError;
use crate::types::validator::ValidatorVerifier;
use crate::types::Version;
use getset::Getters;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerInfo {
    commit_info: BlockInfo,
    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}

impl LedgerInfo {
    pub fn new(commit_info: BlockInfo, consensus_data_hash: HashValue) -> Self {
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
    use crate::crypto::hash::prefixed_sha3;
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
            let mut hasher_bytes = [0u8; 32];
            digest.finalize(&mut hasher_bytes);
            hasher_bytes
        };

        let actual = ledger_info.hash();

        assert_eq!(expected, actual.hash());
    }
}
