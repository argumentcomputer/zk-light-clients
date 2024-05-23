//! # Waypoint Module
//!
//! This module provides the `Waypoint` structure and
//! associated methods for handling waypoints in the
//! Aptos Light Client.
//!
//! The `Waypoint` structure represents a waypoint on the Aptos chain,
//! which is a value that clients can use to bootstrap securely to a ledger.

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue, HASH_LENGTH};
use crate::serde_error;
use crate::types::epoch_state::EpochState;
use crate::types::error::TypesError;
use crate::types::ledger_info::LedgerInfo;
use crate::types::utils::U64_SIZE;
use crate::types::Version;
use bytes::{Buf, BufMut, BytesMut};
use getset::CopyGetters;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Length in bytes of the serialized `Waypoint`.
pub const WAYPOINT_SIZE: usize = U64_SIZE + HASH_LENGTH;

#[derive(Debug, CopyGetters, PartialEq, Eq, Clone, Copy)]
pub struct Waypoint {
    /// The version of the reconfiguration transaction that is being approved by this waypoint.
    #[getset(get_copy = "pub")]
    pub(crate) version: Version,
    /// The hash of the chosen fields of LedgerInfo.
    pub(crate) value: HashValue,
}

/// `Waypoint` is a structure representing a waypoint,
/// which is a value that clients can use to bootstrap securely to a ledger.
impl Waypoint {
    /// Generate a new waypoint given any LedgerInfo.
    ///
    /// # Arguments
    ///
    /// * `ledger_info: &LedgerInfo` - The ledger info.
    ///
    /// # Returns
    ///
    /// A new `Waypoint`.
    pub fn new_any(ledger_info: &LedgerInfo) -> Self {
        let converter = Ledger2WaypointConverter::new(ledger_info);
        Self {
            version: ledger_info.version(),
            value: converter.hash(),
        }
    }

    /// Creates a `Waypoint` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `Waypoint`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `Waypoint` could
    /// be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let version = bytes.get_u64_le();

        let value = HashValue::from_slice(
            bytes
                .chunk()
                .get(..HASH_LENGTH)
                .ok_or_else(|| serde_error!("Waypoint", "Not enough data for value"))?,
        )
        .map_err(|e| serde_error!("Waypoint", e))?;

        bytes.advance(HASH_LENGTH);

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "TransactionInfo",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self { version, value })
    }

    ///. Converts the `Waypoint` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `Waypoint`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u64_le(self.version);
        bytes.put_slice(self.value.as_ref());
        bytes.to_vec()
    }
}

impl<'de> Deserialize<'de> for Waypoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(::serde::Deserialize)]
        #[serde(rename = "Waypoint")]
        struct Value(Version, HashValue);

        let value = Value::deserialize(deserializer)?;
        Ok(Waypoint {
            version: value.0,
            value: value.1,
        })
    }
}

impl Serialize for Waypoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("Waypoint", &(self.version, self.value))
    }
}

// This structure only exists to hash the LedgerInfo
#[derive(Debug, PartialEq, Eq, Clone, Default, Serialize)]
struct Ledger2WaypointConverter {
    epoch: u64,
    root_hash: HashValue,
    version: Version,
    timestamp_usecs: u64,
    next_epoch_state: Option<EpochState>,
}

impl Ledger2WaypointConverter {
    /// Creates a new `Ledger2WaypointConverter` from a `LedgerInfo`.
    ///
    /// # Arguments
    ///
    /// * `ledger_info: &LedgerInfo` - The ledger info.
    ///
    /// # Returns
    ///
    /// A new `Ledger2WaypointConverter`.
    pub(crate) fn new(ledger_info: &LedgerInfo) -> Self {
        Self {
            epoch: ledger_info.epoch(),
            root_hash: ledger_info.transaction_accumulator_hash(),
            version: ledger_info.version(),
            timestamp_usecs: ledger_info.timestamp_usecs(),
            next_epoch_state: ledger_info.next_epoch_state().cloned(),
        }
    }

    /// Converts the `Ledger2WaypointConverter` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `Ledger2WaypointConverter`.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u64_le(self.epoch);
        bytes.put_slice(self.root_hash.as_ref());
        bytes.put_u64_le(self.version);
        bytes.put_u64_le(self.timestamp_usecs);
        match &self.next_epoch_state {
            Some(state) => {
                bytes.put_u8(1); // Indicate that there is a next_epoch_state
                bytes.put_slice(&state.to_bytes());
            }
            None => {
                bytes.put_u8(0); // Indicate that there is no next_epoch_state
            }
        }
        bytes.to_vec()
    }
}

impl CryptoHash for Ledger2WaypointConverter {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"Ledger2WaypointConverter"),
            vec![&self.to_bytes()],
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tiny_keccak::{Hasher, Sha3};

    #[test]
    fn test_hash() {
        let ledger_to_waypoint = Ledger2WaypointConverter::default();

        let expected = {
            let mut digest = Sha3::v256();
            digest.update(&prefixed_sha3(b"Ledger2WaypointConverter"));
            digest.update(&bcs::to_bytes(&ledger_to_waypoint).unwrap());
            let mut hasher_bytes = [0u8; HASH_LENGTH];
            digest.finalize(&mut hasher_bytes);
            hasher_bytes
        };

        let actual = ledger_to_waypoint.hash();

        assert_eq!(expected, actual.hash());
    }

    #[cfg(feature = "aptos")]
    mod aptos {
        use proptest::prelude::ProptestConfig;
        use proptest::proptest;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(10))]
            #[test]
            fn test_bytes_conversion_waypoint(
                validators in 130..136,
                signers in 95..101
            ) {
                use super::*;
                use crate::aptos_test_utils::wrapper::AptosWrapper;

                let mut aptos_wrapper = AptosWrapper::new(2, validators as usize, signers as usize).unwrap();

                aptos_wrapper.generate_traffic().unwrap();
                aptos_wrapper.commit_new_epoch().unwrap();

                let waypoint = aptos_wrapper.trusted_state().waypoint();

                let bytes = bcs::to_bytes(&waypoint).unwrap();

                let waypoint_deserialized = Waypoint::from_bytes(&bytes).unwrap();
                let waypoint_serialized = waypoint_deserialized.to_bytes();

                assert_eq!(bytes, waypoint_serialized);
            }
        }
    }
}
