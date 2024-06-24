// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: BUSL-1.1

//! This module defines LedgerInfo and LedgerInfoWithSignatures structs which are used to
//! represent the information about the latest committed block and the signatures of the
//! validators over the LedgerInfo.
//!
//! # Note
//!
//! In this module we define some constants that represent the offsets and lengths of the
//! fields in the serialized LedgerInfo and LedgerInfoWithSignatures structs. These constants
//! represent offset and length of the fields bytes.

// SPDX-License-Identifier: BUSL-1.1
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue, HASH_LENGTH};
use crate::crypto::sig::AggregateSignature;
use crate::serde_error;
use crate::types::block_info::BlockInfo;
use crate::types::epoch_state::EpochState;
use crate::types::error::{TypesError, VerifyError};
use crate::types::utils::ENUM_VARIANT_LEN;
use crate::types::validator::ValidatorVerifier;
use crate::types::Version;
use bytes::{Buf, BufMut, BytesMut};
use getset::Getters;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

/// `LedgerInfo` is a structure representing the information
/// about the latest committed block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerInfo {
    commit_info: BlockInfo,
    /// Hash of consensus specific data that is opaque to all parts of the system other than
    /// consensus.
    consensus_data_hash: HashValue,
}

impl LedgerInfo {
    /// Creates a new `LedgerInfo`.
    ///
    /// # Arguments
    ///
    /// * `commit_info: BlockInfo` - The commit info.
    /// * `consensus_data_hash: HashValue` - The hash of consensus specific data.
    ///
    /// # Returns
    ///
    /// A new `LedgerInfo`.
    pub const fn new(commit_info: BlockInfo, consensus_data_hash: HashValue) -> Self {
        Self {
            commit_info,
            consensus_data_hash,
        }
    }

    /// Returns the epoch of the `LedgerInfo`.
    ///
    /// # Returns
    ///
    /// The epoch of the `LedgerInfo` contained in its
    /// `BlockInfo`.
    pub fn epoch(&self) -> u64 {
        self.commit_info.epoch()
    }

    /// Returns the  epoch  of the `LedgerInfo`.
    ///
    /// # Returns
    ///
    /// The epoch of the `LedgerInfo` contained in its
    /// `BlockInfo`.
    pub fn next_block_epoch(&self) -> u64 {
        self.commit_info.next_block_epoch()
    }

    /// Returns the next epoch state of the `LedgerInfo`.
    ///
    /// # Returns
    ///
    /// The next epoch state of the `LedgerInfo`.
    pub fn next_epoch_state(&self) -> Option<&EpochState> {
        self.commit_info.next_epoch_state().as_ref()
    }

    /// Returns the timestamp of the `LedgerInfo`.
    ///
    /// # Returns
    ///
    /// The timestamp of the `LedgerInfo`.
    pub fn timestamp_usecs(&self) -> u64 {
        self.commit_info.timestamp_usecs()
    }

    /// Returns the transaction accumulator hash of the `LedgerInfo`.
    ///
    /// # Returns
    ///
    /// The transaction accumulator hash of the `LedgerInfo`
    pub fn transaction_accumulator_hash(&self) -> HashValue {
        self.commit_info.executed_state_id()
    }

    /// Returns the version of the `LedgerInfo`.
    ///
    /// # Returns
    ///
    /// The version of the `LedgerInfo`.
    pub fn version(&self) -> Version {
        self.commit_info.version()
    }

    /// Converts the `LedgerInfo` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `LedgerInfo`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.commit_info.to_bytes());
        bytes.put_slice(self.consensus_data_hash.as_ref());
        bytes.to_vec()
    }

    /// Creates a `LedgerInfo` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `LedgerInfo`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `LedgerInfo` could be
    /// successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let commit_info = BlockInfo::from_bytes(
            bytes
                .chunk()
                .get(..bytes.len() - HASH_LENGTH)
                .ok_or_else(|| serde_error!("LedgerInfo", "Not enough data for BlockInfo"))?,
        )
        .map_err(|e| serde_error!("LedgerInfo", e))?;

        bytes.advance(bytes.len() - HASH_LENGTH); // Advance the buffer to get the hash

        let consensus_data_hash =
            HashValue::from_slice(bytes.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                serde_error!("LedgerInfo", "Not enough data for consensus data hash")
            })?)
            .map_err(|e| serde_error!("LedgerInfo", e))?;

        bytes.advance(HASH_LENGTH);

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "LedgerInfo",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self {
            commit_info,
            consensus_data_hash,
        })
    }

    /// Estimate the size in bytes for  `LedgerInfo` from the given bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to estimate the size.
    ///
    /// # Returns
    ///
    /// The estimated size in bytes for the structure.
    ///
    /// # Note
    ///
    /// The `LedgerInfo` bytes should start from offset 0 of the slice.
    pub(crate) fn estimate_size_from_bytes(bytes: &[u8]) -> Result<usize, TypesError> {
        Ok(BlockInfo::estimate_size_from_bytes(bytes)? + HASH_LENGTH)
    }
}

impl CryptoHash for LedgerInfo {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"LedgerInfo"),
            vec![&self.to_bytes()],
        ))
    }
}

#[derive(Debug, Clone, Getters, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerInfoWithV0 {
    #[getset(get = "pub")]
    ledger_info: LedgerInfo,
    /// Aggregated BLS signature of all the validators that signed the message. The bitmask in the
    /// aggregated signature can be used to find out the individual validators signing the message
    #[getset(get = "pub")]
    signatures: AggregateSignature,
}

impl LedgerInfoWithV0 {
    pub fn verify_signatures(
        &self,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<(), VerifyError> {
        validator.verify_multi_signatures(self.ledger_info(), &self.signatures)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.ledger_info.to_bytes());
        bytes.put_slice(&self.signatures.to_bytes());
        bytes.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let ledger_info_size = LedgerInfo::estimate_size_from_bytes(bytes)?;
        let agg_sig_size = bytes.len() - ledger_info_size;

        let ledger_info =
            LedgerInfo::from_bytes(bytes.chunk().get(..ledger_info_size).ok_or_else(|| {
                serde_error!("LedgerInfoWithV0", "Not enough data for LedgerInfo")
            })?)?;
        bytes.advance(ledger_info_size);

        let signatures =
            AggregateSignature::from_bytes(bytes.chunk().get(..agg_sig_size).ok_or_else(
                || serde_error!("LedgerInfoWithV0", "Not enough data for AggregateSignature"),
            )?)?;
        bytes.advance(agg_sig_size);

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "LedgerInfoWithV0",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self {
            ledger_info,
            signatures,
        })
    }
}

/// `LedgerInfoWithSignatures` is a structure representing the `LedgerInfo` with
/// the aggregated signatures of the validators that signed the `LedgerInfo`.
///
/// This is  an enum to enable versioning of the `LedgerInfo` struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerInfoWithSignatures {
    V0(LedgerInfoWithV0),
}

impl LedgerInfoWithSignatures {
    /// Converts the `LedgerInfoWithSignatures` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `LedgerInfoWithSignatures`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        match self {
            LedgerInfoWithSignatures::V0(ledger_info_with_v0) => {
                bytes.put_u8(0); // 0 indicates V0
                bytes.extend_from_slice(&ledger_info_with_v0.to_bytes());
            }
        }
        bytes.to_vec()
    }

    /// Creates a `LedgerInfoWithSignatures` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `LedgerInfoWithSignatures`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `LedgerInfoWithSignatures`
    /// could be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let ledger_v0_size = bytes.len() - ENUM_VARIANT_LEN;
        let li_w_sig = match bytes.get_u8() {
            0 => {
                let ledger_info_with_v0 = LedgerInfoWithV0::from_bytes(
                    bytes.chunk().get(..ledger_v0_size).ok_or_else(|| {
                        serde_error!(
                            "LedgerInfoWithSignatures",
                            "Not enough LedgerInfoWithV0 for LedgerInfo"
                        )
                    })?,
                )?;
                bytes.advance(ledger_v0_size);

                LedgerInfoWithSignatures::V0(ledger_info_with_v0)
            }
            _ => return Err(serde_error!("LedgerInfoWithSignatures", "Unknown variant")),
        };

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "LedgerInfoWithSignatures",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(li_w_sig)
    }

    /// Returns the aggregated signatures of the validators
    /// that signed the `LedgerInfoWithSignatures`.
    ///
    /// # Returns
    ///
    /// The aggregated signatures of the validators
    /// that signed the `LedgerInfoWithSignatures`.
    pub const fn signatures(&self) -> &AggregateSignature {
        match &self {
            LedgerInfoWithSignatures::V0(ledger) => &ledger.signatures,
        }
    }
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

#[cfg(all(test, feature = "aptos"))]
mod test {
    use proptest::prelude::ProptestConfig;
    use proptest::proptest;

    #[test]
    fn test_ledger_info_hash() {
        use super::*;
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::crypto::hash::CryptoHash as LcCryptoHash;
        use aptos_crypto::hash::CryptoHash as AptosCryptoHash;

        let mut aptos_wrapper = AptosWrapper::new(2, 130, 130).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let aptos_li = aptos_wrapper.get_latest_li().unwrap().ledger_info().clone();
        let intern_li_hash = LcCryptoHash::hash(
            &LedgerInfo::from_bytes(&bcs::to_bytes(&aptos_li).unwrap()).unwrap(),
        );
        let aptos_li_hash = AptosCryptoHash::hash(&aptos_li);

        assert_eq!(intern_li_hash.to_vec(), aptos_li_hash.to_vec());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_bytes_conversion_ledger_info(
            validators in 130..136,
            signers in 95..101
        ) {
            use super::*;
            use crate::aptos_test_utils::wrapper::AptosWrapper;

            let mut aptos_wrapper = AptosWrapper::new(2, validators as usize, signers as usize).unwrap();

            aptos_wrapper.generate_traffic().unwrap();
            aptos_wrapper.commit_new_epoch().unwrap();

            let ledger_info_bytes = bcs::to_bytes(
                &aptos_wrapper
                    .get_latest_li().expect("Could not retrieve latest LedgerInfoWithSignatures")
                    .ledger_info()
            ).expect("Failed to serialize ValidatorVerifier");

            let ledger_info_deserialized = LedgerInfo::from_bytes(&ledger_info_bytes).unwrap();
            let ledger_info_serialized = ledger_info_deserialized.to_bytes();

            assert_eq!(ledger_info_bytes, ledger_info_serialized);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_bytes_conversion_ledger_info_w_sig(
            validators in 130..136,
            signers in 95..101
        ) {
            use super::*;
            use crate::aptos_test_utils::wrapper::AptosWrapper;

            let mut aptos_wrapper = AptosWrapper::new(2, validators as usize, signers as usize).unwrap();

            fn test_li(aptos_wrapper: &AptosWrapper) {
                let latest_li = aptos_wrapper.get_latest_li().unwrap();
                let latest_li_bytes = bcs::to_bytes(&latest_li).unwrap();

                let intern_li_w_sig =
                    LedgerInfoWithSignatures::from_bytes(&latest_li_bytes).unwrap();

                // Test LedgerInfo
                let ledger_info = bcs::to_bytes(latest_li.ledger_info()).unwrap();
                let intern_li = LedgerInfo::from_bytes(&ledger_info).unwrap();
                assert_eq!(&intern_li, intern_li_w_sig.ledger_info());
                let intern_li_bytes = intern_li.to_bytes();
                assert_eq!(ledger_info, intern_li_bytes);

                // Test AggregateSignature
                let sig = bcs::to_bytes(latest_li.signatures()).unwrap();
                let intern_sig = AggregateSignature::from_bytes(&sig).unwrap();
                assert_eq!(&intern_sig, intern_li_w_sig.signatures());
                let intern_sig_bytes = intern_sig.to_bytes();
                assert_eq!(sig, intern_sig_bytes);

                // Test LedgerInfoWithSignatures
                let intern_li_w_sig =
                    LedgerInfoWithSignatures::from_bytes(&latest_li_bytes).unwrap();
                let intern_li_w_sig_bytes = intern_li_w_sig.to_bytes();
                assert_eq!(latest_li_bytes, intern_li_w_sig_bytes);
            }

            aptos_wrapper.generate_traffic().unwrap();

            test_li(&aptos_wrapper);

            aptos_wrapper.commit_new_epoch().unwrap();

            test_li(&aptos_wrapper);
        }
    }
}
