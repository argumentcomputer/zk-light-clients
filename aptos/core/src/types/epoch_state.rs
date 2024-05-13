//! # Epoch State Module
//!
//! This module provides the `EpochState` structure and
//! associated methods for handling epoch state in the
//! Aptos Light Client.
//!
//! The `EpochState` structure represents the state of
//! an epoch in the blockchain, including the epoch number
//! and the validator verifier.

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures, U64_SIZE};
use crate::types::validator::{ValidatorVerifier, VALIDATOR_VERIFIER_SIZE};
use anyhow::ensure;
use bytes::{Buf, BufMut, BytesMut};
use getset::Getters;
use serde::{Deserialize, Serialize};

/// Length in bytes of the serialized `EpochState`.
pub const EPOCH_STATE_SIZE: usize = U64_SIZE + VALIDATOR_VERIFIER_SIZE;

/// `EpochState` is a structure representing the state of an epoch in the blockchain.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct EpochState {
    pub epoch: u64,
    pub verifier: ValidatorVerifier,
}

impl EpochState {
    /// Checks if epoch change verification is required.
    ///
    /// # Arguments
    ///
    /// * `epoch: u64` - The epoch number.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether epoch change verification is required.
    pub const fn epoch_change_verification_required(&self, epoch: u64) -> bool {
        self.epoch < epoch
    }

    /// Checks if a ledger info is stale.
    ///
    /// # Arguments
    ///
    /// * `ledger_info: &LedgerInfo` - The ledger info to check.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the ledger info is stale.
    pub fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        ledger_info.epoch() < self.epoch
    }

    /// Verifies signatures over a given `LedgerInfoWithSignatures`.
    ///
    /// # Arguments
    ///
    /// * `ledger_info: &LedgerInfoWithSignatures` - The ledger
    /// info with signatures to verify.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the ledger info with signatures
    /// is valid, and `Err` otherwise.
    pub fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }

    /// Converts the `EpochState` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `EpochState`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u64_le(self.epoch);
        bytes.put_slice(&self.verifier.to_bytes());
        bytes.to_vec()
    }

    /// Creates an `EpochState` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `EpochState`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `EpochState` could
    /// be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let epoch = bytes.get_u64_le();
        let verifier = ValidatorVerifier::from_bytes(
            bytes
                .chunk()
                .get(..VALIDATOR_VERIFIER_SIZE)
                .ok_or_else(|| serde_error!("EpochState", "Not enough data for verifier"))?,
        )
        .map_err(|e| serde_error!("EpochState", e))?;
        bytes.advance(VALIDATOR_VERIFIER_SIZE);

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "EpochState",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self { epoch, verifier })
    }
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    #[test]
    fn test_bytes_conversion_epoch_state() {
        use super::*;
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::NBR_VALIDATORS;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let epoch_state = aptos_wrapper
            .get_latest_li()
            .unwrap()
            .ledger_info()
            .commit_info()
            .next_epoch_state()
            .unwrap()
            .clone();

        let bytes = bcs::to_bytes(&epoch_state).unwrap();

        let epoch_state_deserialized = EpochState::from_bytes(&bytes).unwrap();
        let epoch_state_serialized = epoch_state_deserialized.to_bytes();

        assert_eq!(bytes, epoch_state_serialized);
    }
}
