// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
use crate::types::epoch_state::EpochState;
use crate::types::error::TypesError;
use crate::types::ledger_info::{
    LedgerInfo, LedgerInfoWithSignatures, AGG_SIGNATURE_LEN, ENUM_VARIANT_LEN, LEDGER_INFO_LEN,
};
use crate::types::utils::{read_leb128, write_leb128};
use crate::types::waypoint::Waypoint;
use crate::types::Version;
use anyhow::{bail, ensure, format_err};
use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};

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
    pub fn version(&self) -> Version {
        self.waypoint().version()
    }

    pub fn waypoint(&self) -> Waypoint {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { waypoint, .. } => *waypoint,
        }
    }

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

    fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.is_ledger_info_stale(ledger_info),
        }
    }

    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.verify(ledger_info),
        }
    }

    /// The main LC method
    /// Expects to receive an `EpochChangeProof` containing one `LedgerInfoWithSignatures`
    /// that represents an epoch transition from trusted_state.epoch -> trusted_state.epoch +1,
    /// and verifies it.
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

            // If the latest ledger info is in the same epoch as the new verifier, verify it and
            // use it as latest state, otherwise fallback to the epoch change ledger info.
            let new_epoch = new_epoch_state.epoch;

            // With the current hardcoded latest_li from epoch_change_proof, we always fall on the first branch.
            let verified_ledger_info = if epoch_change_li == latest_li {
                latest_li
            } else if latest_li.ledger_info().epoch() == new_epoch {
                new_epoch_state.verify(latest_li)?;
                latest_li
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
            };
            let new_waypoint = Waypoint::new_any(verified_ledger_info.ledger_info());

            let new_state = TrustedState::EpochState {
                waypoint: new_waypoint,
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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let mut buf = BytesMut::from(bytes);

        const WAYPOINT_BYTES_LEN: usize = 40;

        match buf.get_u8() {
            0 => {
                println!("cycle-tracker-start: waypoint_from_bytes");
                let waypoint = Waypoint::from_bytes(buf.chunk())?;
                println!("cycle-tracker-end: waypoint_from_bytes");
                Ok(TrustedState::EpochWaypoint(waypoint))
            }
            1 => {
                println!("cycle-tracker-start: waypoint_from_bytes");
                let waypoint =
                    Waypoint::from_bytes(buf.chunk().get(..WAYPOINT_BYTES_LEN).ok_or_else(
                        || TypesError::DeserializationError {
                            structure: String::from("Waypoint"),
                            source: "Not enough data for value".into(),
                        },
                    )?)?;

                buf.advance(WAYPOINT_BYTES_LEN);
                println!("cycle-tracker-end: waypoint_from_bytes");
                println!("cycle-tracker-start: epoch_state_from_bytes");
                let epoch_state = EpochState::from_bytes(buf.chunk())?;
                println!("cycle-tracker-end: epoch_state_from_bytes");
                Ok(TrustedState::EpochState {
                    waypoint,
                    epoch_state,
                })
            }
            _ => Err(TypesError::DeserializationError {
                structure: String::from("TrustedState"),
                source: "Unknown variant".into(),
            }),
        }
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
            let new_waypoint = Waypoint::new_any(new_li);
            let new_trusted_state = TrustedState::EpochState {
                waypoint: new_waypoint,
                epoch_state: new_epoch_state.clone(),
            };
            trusted_state = new_trusted_state;
        }

        Ok(self.ledger_info_with_sigs.last().unwrap())
    }

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let mut buf = BytesMut::from(bytes);
        println!("cycle-tracker-start: read_leb128_advance");
        // Read the length of the vector from LEB128
        let (len, bytes_read) = read_leb128(&buf)?;
        buf.advance(bytes_read);
        println!("cycle-tracker-end: read_leb128_advance");

        // Read each LedgerInfoWithSignatures from bytes
        let mut ledger_info_with_sigs = Vec::new();
        for i in 0..len {
            println!("cycle-tracker-start: li_w_signature_from_bytes");
            let ledger_info_with_sig = LedgerInfoWithSignatures::from_bytes(
                buf.chunk()
                    .get(..ENUM_VARIANT_LEN + LEDGER_INFO_LEN + AGG_SIGNATURE_LEN)
                    .ok_or_else(|| TypesError::DeserializationError {
                        structure: String::from("EpochChangeProof"),
                        source: format!(
                            "Not enough data for LedgerInfoWithSignatures at index {i}"
                        )
                        .into(),
                    })?,
            )?;
            println!("cycle-tracker-end: li_w_signature_from_bytes");
            ledger_info_with_sigs.push(ledger_info_with_sig);
            buf.advance(ENUM_VARIANT_LEN + LEDGER_INFO_LEN + AGG_SIGNATURE_LEN);
        }

        // Read the `more` field
        let more = buf.get_u8() != 0;

        Ok(EpochChangeProof {
            ledger_info_with_sigs,
            more,
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "aptos")]
    fn assess_equality(bytes: Vec<u8>) {
        use crate::types::trusted_state::TrustedState;

        let trusted_state_deserialized = TrustedState::from_bytes(&bytes).unwrap();
        let trusted_state_serialized = trusted_state_deserialized.to_bytes();

        assert_eq!(bytes, trusted_state_serialized);
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_trusted_state_epoch() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::NBR_VALIDATORS;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        // New epoch TrustedState
        let trusted_state = aptos_wrapper.trusted_state().clone();

        let bytes = bcs::to_bytes(&trusted_state).unwrap();

        assess_equality(bytes);

        // No new epoch
        aptos_wrapper.generate_traffic();

        let trusted_state = aptos_wrapper.trusted_state().clone();

        let bytes = bcs::to_bytes(&trusted_state).unwrap();

        assess_equality(bytes);
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_epoch_change_proof() {
        use super::*;
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::NBR_VALIDATORS;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        // New epoch TrustedState
        let state_proof = aptos_wrapper.new_state_proof(*aptos_wrapper.current_version());

        let bytes = bcs::to_bytes(state_proof.epoch_changes()).unwrap();

        let intern_epoch_change_proof = EpochChangeProof::from_bytes(&bytes).unwrap();

        assert_eq!(bytes, intern_epoch_change_proof.to_bytes());
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_trusted_state_hash() {
        use super::*;
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::crypto::hash::CryptoHash as LcCryptoHash;
        use crate::NBR_VALIDATORS;
        use aptos_crypto::hash::CryptoHash as AptosCryptoHash;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

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
