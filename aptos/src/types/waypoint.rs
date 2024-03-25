// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
use crate::types::epoch_state::EpochState;
use crate::types::ledger_info::LedgerInfo;
use crate::types::Version;
use getset::CopyGetters;
use serde::Serialize;
use test_strategy::Arbitrary;

#[derive(Debug, CopyGetters, PartialEq, Eq, Clone, Copy, Arbitrary)]
pub struct Waypoint {
    /// The version of the reconfiguration transaction that is being approved by this waypoint.
    #[getset(get_copy = "pub")]
    version: Version,
    /// The hash of the chosen fields of LedgerInfo.
    value: HashValue,
}

impl Waypoint {
    /// Generate a new waypoint given any LedgerInfo.
    pub fn new_any(ledger_info: &LedgerInfo) -> Self {
        let converter = Ledger2WaypointConverter::new(ledger_info);
        Self {
            version: ledger_info.version(),
            value: converter.hash(),
        }
    }
}

// #[derive(CryptoHasher, BCSCryptoHash)]
// This is just made to hash the LedgerInfo
#[derive(Debug, PartialEq, Eq, Clone, Default, Serialize)]
struct Ledger2WaypointConverter {
    epoch: u64,
    root_hash: HashValue,
    version: Version,
    timestamp_usecs: u64,
    next_epoch_state: Option<EpochState>,
}

impl Ledger2WaypointConverter {
    pub fn new(ledger_info: &LedgerInfo) -> Self {
        Self {
            epoch: ledger_info.epoch(),
            root_hash: ledger_info.transaction_accumulator_hash(),
            version: ledger_info.version(),
            timestamp_usecs: ledger_info.timestamp_usecs(),
            next_epoch_state: ledger_info.next_epoch_state().cloned(),
        }
    }
}

impl CryptoHash for Ledger2WaypointConverter {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"Ledger2WaypointConverter"),
            vec![&bcs::to_bytes(&self).unwrap()],
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::hash::prefixed_sha3;
    use tiny_keccak::{Hasher, Sha3};

    #[test]
    fn test_hash() {
        let ledger_to_waypoint = Ledger2WaypointConverter::default();

        let expected = {
            let mut digest = Sha3::v256();
            digest.update(&prefixed_sha3(b"Ledger2WaypointConverter"));
            digest.update(&bcs::to_bytes(&ledger_to_waypoint).unwrap());
            let mut hasher_bytes = [0u8; 32];
            digest.finalize(&mut hasher_bytes);
            hasher_bytes
        };

        let actual = ledger_to_waypoint.hash();

        assert_eq!(expected, actual.hash());
    }
}
