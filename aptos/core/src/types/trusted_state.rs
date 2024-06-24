// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: BUSL-1.1

//! # Trusted State Module
//!
//! This module provides the `TrustedState` to keeps track
//! of our light clients' latest, trusted view of the ledger state.
//! It can be leveraged alongside an`EpochChangeProof`
//! to "ratchet" our view forward to a newer state.

// SPDX-License-Identifier: BUSL-1.1
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
use crate::serde_error;
use crate::types::epoch_state::EpochState;
use crate::types::error::TypesError;
use crate::types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use crate::types::utils::{read_leb128, write_leb128};
use crate::types::waypoint::{Waypoint, WAYPOINT_SIZE};
use crate::types::Version;
use anyhow::{bail, ensure, format_err};
use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};

/// `TrustedState` keeps track of our light clients' latest,
/// trusted view of the ledger state. It can be leveraged
/// alongside proofs from a state proof to "ratchet"
/// our view forward to a newer state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustedState {
    /// The current trusted state is an epoch waypoint, which is a commitment to
    /// an epoch change ledger info. Most light clients will start here when
    /// syncing for the first time.
    EpochWaypoint(Waypoint),
    /// The current trusted state is inside a verified epoch (which includes the
    /// validator set inside that epoch).
    EpochState {
        /// The current trusted version and a commitment to a ledger info inside
        /// the current trusted epoch.
        waypoint: Waypoint,
        /// The current epoch and validator set inside that epoch.
        epoch_state: EpochState,
    },
}

impl TrustedState {
    /// Returns the epoch for the `TrustedState`.
    ///
    /// # Returns
    ///
    /// The epoch of the `TrustedState`.
    pub const fn epoch(&self) -> Option<u64> {
        match self {
            TrustedState::EpochState { epoch_state, .. } => Some(epoch_state.epoch),
            _ => None,
        }
    }

    /// Returns the transaction version for the `TrustedState`.
    ///
    /// # Returns
    ///
    /// The transaction version of the `TrustedState`.
    pub fn version(&self) -> Version {
        self.waypoint().version()
    }

    /// Returns the waypoint of the `TrustedState`.
    ///
    /// # Returns
    ///
    /// The waypoint of the `TrustedState`.
    pub fn waypoint(&self) -> Waypoint {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { waypoint, .. } => *waypoint,
        }
    }
    /// Checks if epoch change verification is required. This
    /// is the case if the current epoch is behind the target epoch.
    ///
    /// # Arguments
    ///
    /// * `epoch: u64` - The epoch number.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether epoch change verification is required.
    fn epoch_change_verification_required(&self, epoch: u64) -> bool {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => {
                epoch_state.epoch_change_verification_required(epoch)
            }
        }
    }

    /// Checks if a ledger info is stale. This is the case if the ledger info's
    /// epoch is behind the current trusted epoch.
    ///
    /// # Arguments
    ///
    /// * `ledger_info: &LedgerInfo` - The ledger info to check.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the ledger info is stale.
    fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.is_ledger_info_stale(ledger_info),
        }
    }
    /// Verifies a ledger info with signatures against  the current trusted state.
    /// This will verify the signatures and the epoch number.
    ///
    /// # Arguments
    ///
    /// * `ledger_info: &LedgerInfoWithSignatures` - The
    ///   ledger info with signatures to verify.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the ledger info with
    /// signatures is valid, and `Err` otherwise.

    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.verify(ledger_info),
        }
    }

    /// The main LC method that verifies and ratchets the
    /// trusted state. Expects to receive an `EpochChangeProof`
    /// containing one `LedgerInfoWithSignatures` that
    /// represents an epoch transition from
    /// trusted_state.epoch -> trusted_state.epoch +1, and
    /// verifies it.
    ///
    /// # Arguments
    ///
    /// * `epoch_change_proof: &'a EpochChangeProof` - The epoch change proof to verify.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the trusted state could be successfully verified and ratcheted, and `Err` otherwise.
    ///
    pub fn verify_and_ratchet_inner<'a>(
        &self,
        epoch_change_proof: &'a EpochChangeProof,
    ) -> anyhow::Result<TrustedStateChange<'a>> {
        // Abort early if the response is stale.
        let curr_version = self.version();
        let latest_li = epoch_change_proof
            .ledger_info_with_sigs
            .last()
            .ok_or_else(|| format_err!("epoch_change_proof doesn't carry a LedgerInfo"))?;
        let target_version = latest_li.ledger_info().version();
        ensure!(
            target_version >= curr_version,
            "The target latest ledger info version is stale ({}) and behind our current trusted version ({})",
            target_version, curr_version,
        );

        if self.epoch_change_verification_required(latest_li.ledger_info().next_block_epoch()) {
            // Verify the EpochChangeProof to move us into the latest epoch.
            let epoch_change_li = epoch_change_proof.verify(self)?;
            let new_epoch_state = epoch_change_li
                .ledger_info()
                .next_epoch_state()
                .cloned()
                .ok_or_else(|| {
                    format_err!(
                        "A valid EpochChangeProof will never return a non-epoch change ledger info"
                    )
                })?;

            let verified_ledger_info = if epoch_change_li == latest_li {
                latest_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
            };

            let new_state = TrustedState::EpochState {
                waypoint: Waypoint::new_any(verified_ledger_info.ledger_info()),
                epoch_state: new_epoch_state,
            };

            Ok(TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li: epoch_change_li,
            })
        } else {
            Err(format_err!("Received proof is not for an epoch change"))
        }
    }

    /// Converts the `TrustedState` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `TrustedState`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();

        match self {
            TrustedState::EpochWaypoint(waypoint) => {
                bytes.put_u8(0); // 0 indicates EpochWaypoint
                bytes.put_slice(&waypoint.to_bytes());
            }
            TrustedState::EpochState {
                waypoint,
                epoch_state,
            } => {
                bytes.put_u8(1); // 1 indicates EpochState
                bytes.put_slice(&waypoint.to_bytes());
                bytes.put_slice(&epoch_state.to_bytes());
            }
        }

        bytes.to_vec()
    }

    /// Creates a `TrustedState` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `TrustedState`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `TrustedState` could
    /// be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let epoch_state_size = bytes.len() - WAYPOINT_SIZE - 1;

        let trusted_state = match bytes.get_u8() {
            0 => {
                let waypoint =
                    Waypoint::from_bytes(bytes.chunk().get(..WAYPOINT_SIZE).ok_or_else(|| {
                        serde_error!("TrustedState", "Not enough data for Waypoint")
                    })?)?;
                TrustedState::EpochWaypoint(waypoint)
            }
            1 => {
                let waypoint =
                    Waypoint::from_bytes(bytes.chunk().get(..WAYPOINT_SIZE).ok_or_else(|| {
                        serde_error!("TrustedState", "Not enough data for Waypoint")
                    })?)?;
                bytes.advance(WAYPOINT_SIZE);

                let epoch_state =
                    EpochState::from_bytes(bytes.chunk().get(..epoch_state_size).ok_or_else(
                        || serde_error!("TrustedState", "Not enough data for epoch state"),
                    )?)?;
                bytes.advance(epoch_state_size);
                TrustedState::EpochState {
                    waypoint,
                    epoch_state,
                }
            }
            _ => return Err(serde_error!("TrustedState", "Unknown variant")),
        };

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "LedgerInfo",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(trusted_state)
    }
}

impl CryptoHash for TrustedState {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"TrustedState"),
            vec![&self.to_bytes()],
        ))
    }
}

/// `TrustedStateChange` is an enum representing the
/// possible changes in the trusted state.
///
/// It can either be a version change, an epoch change, or no change.
#[derive(Debug)]
pub enum TrustedStateChange<'a> {
    /// We have a newer `TrustedState` but it's still in the same epoch, so only
    /// the latest trusted version changed.
    Version { new_state: TrustedState },
    /// We have a newer `TrustedState` and there was at least one epoch change,
    /// so we have a newer trusted version and a newer trusted validator set.
    Epoch {
        new_state: TrustedState,
        latest_epoch_change_li: &'a LedgerInfoWithSignatures,
    },
    /// The latest ledger info is at the same version as the trusted state and matches the hash.
    NoChange,
}

/// A vector of LedgerInfo with contiguous increasing epoch numbers to prove a sequence of
/// epoch changes from the first LedgerInfo's epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochChangeProof {
    pub ledger_info_with_sigs: Vec<LedgerInfoWithSignatures>,
    pub more: bool,
}

impl EpochChangeProof {
    /// Verify the proof is correctly chained with known epoch and validator
    /// verifier and return the [`LedgerInfoWithSignatures`] to start target epoch.
    ///
    /// In case a waypoint is present, it's going to be used for verifying the
    /// very first epoch change (it's the responsibility of the caller to not
    /// pass a waypoint in case it's not needed).
    ///
    /// We will also skip any stale ledger info's in the [`EpochChangeProof`].
    ///
    /// # Arguments
    ///
    /// * `verifier` - The [`TrustedState`] to verify the [`EpochChangeProof`] against.
    ///
    /// # Returns
    ///
    /// The latest [`LedgerInfoWithSignatures`] in the [`EpochChangeProof`].
    pub fn verify(&self, verifier: &TrustedState) -> anyhow::Result<&LedgerInfoWithSignatures> {
        ensure!(
            !self.ledger_info_with_sigs.is_empty(),
            "The EpochChangeProof is empty"
        );
        ensure!(
            !verifier
                .is_ledger_info_stale(self.ledger_info_with_sigs.last().unwrap().ledger_info()),
            "The EpochChangeProof is stale as our verifier is already ahead \
             of the entire EpochChangeProof"
        );
        let mut trusted_state: TrustedState = verifier.clone();

        for ledger_info_with_sigs in self
            .ledger_info_with_sigs
            .iter()
            // Skip any stale ledger infos in the proof prefix. Note that with
            // the assertion above, we are guaranteed there is at least one
            // non-stale ledger info in the proof.
            //
            // It's useful to skip these stale ledger infos to better allow for
            // concurrent client requests.
            //
            // For example, suppose the following:
            //
            // 1. My current trusted state is at epoch 5.
            // 2. I make two concurrent requests to two validators A and B, who
            //    live at epochs 9 and 11 respectively.
            //
            // If A's response returns first, I will ratchet my trusted state
            // to epoch 9. When B's response returns, I will still be able to
            // ratchet forward to 11 even though B's EpochChangeProof
            // includes a bunch of stale ledger infos (for epochs 5, 6, 7, 8).
            //
            // Of course, if B's response returns first, we will reject A's
            // response as it's completely stale.
            .skip_while(|&ledger_info_with_sigs| {
                verifier.is_ledger_info_stale(ledger_info_with_sigs.ledger_info())
            })
        {
            // Try to verify each (epoch -> epoch + 1) jump in the EpochChangeProof.
            trusted_state.verify(ledger_info_with_sigs)?;
            // While the original verification could've been via waypoints,
            // all the next epoch changes are verified using the (already
            // trusted) validator sets.
            let new_li = ledger_info_with_sigs.ledger_info();

            let new_epoch_state = new_li
                .next_epoch_state()
                .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;

            let new_trusted_state = TrustedState::EpochState {
                waypoint: Waypoint::new_any(new_li),
                epoch_state: new_epoch_state.clone(),
            };

            trusted_state = new_trusted_state;
        }

        Ok(self.ledger_info_with_sigs.last().unwrap())
    }

    /// Converts the `EpochChangeProof` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `EpochChangeProof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();

        // Write the length of the vector as LEB128
        bytes.extend_from_slice(&write_leb128(self.ledger_info_with_sigs.len() as u64));

        // Write each LedgerInfoWithSignatures to bytes
        for ledger_info_with_sig in &self.ledger_info_with_sigs {
            bytes.extend_from_slice(&ledger_info_with_sig.to_bytes());
        }

        // Write the `more` field
        bytes.put_u8(u8::from(self.more));

        bytes.to_vec()
    }

    /// Creates an `EpochChangeProof` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `EpochChangeProof`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `EpochChangeProof`
    /// could be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        // Read the length of the vector from LEB128
        let (len, bytes_read) = read_leb128(bytes)
            .map_err(|_| serde_error!("EpochChangeProof", "Not enough data for length"))?;
        bytes.advance(bytes_read);

        // Total length for LedgerInfoWithSignatures
        let total_len = bytes.remaining() - 1;

        if total_len % len as usize != 0 {
            return Err(serde_error!(
                "EpochChangeProof",
                "Invalid data length for ledger_info_with_sigs"
            ));
        }

        // Read each LedgerInfoWithSignatures from bytes
        let mut ledger_info_with_sigs = Vec::new();
        for i in 0..len {
            let ledger_info_with_sig = LedgerInfoWithSignatures::from_bytes(
                bytes
                    .chunk()
                    .get(..total_len / len as usize)
                    .ok_or_else(|| {
                        serde_error!(
                            "EpochChangeProof",
                            format!("Not enough data for LedgerInfoWithSignatures at index {i}")
                        )
                    })?,
            )?;

            ledger_info_with_sigs.push(ledger_info_with_sig);
            bytes.advance(total_len / len as usize);
        }

        // Read the `more` field
        let more = bytes.get_u8() != 0;

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "EpochChangeProof",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(EpochChangeProof {
            ledger_info_with_sigs,
            more,
        })
    }
}

#[cfg(all(test, feature = "aptos"))]
mod test {
    use proptest::prelude::ProptestConfig;
    use proptest::proptest;

    fn assess_equality(bytes: &[u8]) {
        use crate::types::trusted_state::TrustedState;

        let trusted_state_deserialized = TrustedState::from_bytes(bytes).unwrap();
        let trusted_state_serialized = trusted_state_deserialized.to_bytes();

        assert_eq!(bytes, trusted_state_serialized);
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_bytes_conversion_trusted_state_epoch(
            validators in 130..136,
            signers in 95..101
        ) {
            use crate::aptos_test_utils::wrapper::AptosWrapper;

            let mut aptos_wrapper = AptosWrapper::new(2, validators as usize, signers as usize).unwrap();

            aptos_wrapper.generate_traffic().unwrap();
            aptos_wrapper.commit_new_epoch().unwrap();

            // New epoch TrustedState
            let trusted_state = aptos_wrapper.trusted_state().clone();

            let bytes = bcs::to_bytes(&trusted_state).unwrap();

            assess_equality(&bytes);

            // No new epoch
            aptos_wrapper.generate_traffic().unwrap();

            let trusted_state = aptos_wrapper.trusted_state().clone();

            let bytes = bcs::to_bytes(&trusted_state).unwrap();

            assess_equality(&bytes);
        }
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_bytes_conversion_epoch_change_proof(
            validators in 130..136,
            signers in 95..101
        ) {
            use super::*;
            use crate::aptos_test_utils::wrapper::AptosWrapper;

            let mut aptos_wrapper = AptosWrapper::new(2, validators as usize, signers as usize).unwrap();

            aptos_wrapper.generate_traffic().unwrap();
            aptos_wrapper.commit_new_epoch().unwrap();

            // New epoch TrustedState
            let state_proof = aptos_wrapper
                .new_state_proof(*aptos_wrapper.current_version())
                .unwrap();

            let bytes = bcs::to_bytes(state_proof.epoch_changes()).unwrap();

            let intern_epoch_change_proof = EpochChangeProof::from_bytes(&bytes).unwrap();

            assert_eq!(bytes, intern_epoch_change_proof.to_bytes());
        }
    }

    #[test]
    fn test_trusted_state_hash() {
        use super::*;
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::crypto::hash::CryptoHash as LcCryptoHash;
        use aptos_crypto::hash::CryptoHash as AptosCryptoHash;

        let mut aptos_wrapper = AptosWrapper::new(2, 130, 130).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let aptos_trusted_state = aptos_wrapper.trusted_state().clone();
        let intern_trusted_state_hash = LcCryptoHash::hash(
            &TrustedState::from_bytes(&bcs::to_bytes(&aptos_trusted_state).unwrap()).unwrap(),
        );
        let aptos_trusted_state_hash = AptosCryptoHash::hash(&aptos_trusted_state);

        assert_eq!(
            intern_trusted_state_hash.to_vec(),
            aptos_trusted_state_hash.to_vec()
        );
    }
}
