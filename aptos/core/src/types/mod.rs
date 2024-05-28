// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

//! # Types Module
//!
//! This module provides the core data structures and types used in the Aptos Light Client.
//!
//! ## Sub-modules
//!
//! - `block_info`: This sub-module contains the `BlockInfo`
//! structure and associated methods. It is used to represent
//! the block information in the blockchain.
//! - `epoch_state`: This sub-module contains the `EpochState`
//! structure and associated methods. It is used to represent
//! the epoch state in the blockchain.
//! - `ledger_info`: This sub-module contains the `LedgerInfo`
//! structure and associated methods. It is used to represent
//! the ledger information from the blockchain.
//! - `transaction`: This sub-module contains the `Transaction`
//! structure and associated methods. It is used to represent
//! the transactions in the blockchain.
//! - `trusted_state`: This sub-module contains the `TrustedState`
//! structure and associated methods. It is used to represent the
//! trusted state for the blockchain from the Light Client perspective.
//! - `validator`: This sub-module contains the `ValidatorConsensusInfo`
//! and `ValidatorVerifier` structures and associated methods. They are
//! used to represent the validator information from the blockchain
//! consensus.
//! - `waypoint`: This sub-module contains the `Waypoint` and
//! `Ledger2WaypointConverter` structures and associated methods.
//! They are used to represent the waypoints over the blockchain
//! state that can be leveraged for bootstrapping securely.
//!
//! For more detailed information, users should refer to the specific
//! documentation for each sub-module.

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::HASH_LENGTH;
use crate::serde_error;
use crate::types::error::TypesError;
use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod block_info;
pub mod epoch_state;
pub mod error;
pub mod ledger_info;
pub mod transaction;
pub mod trusted_state;
pub mod utils;
pub mod validator;
pub mod waypoint;

pub type Round = u64;
pub type Version = u64;

pub const ACCOUNT_ADDRESS_SIZE: usize = HASH_LENGTH;

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct AccountAddress([u8; ACCOUNT_ADDRESS_SIZE]);

impl AccountAddress {
    pub const fn new(address: [u8; ACCOUNT_ADDRESS_SIZE]) -> Self {
        Self(address)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() != ACCOUNT_ADDRESS_SIZE {
            return Err(TypesError::InvalidLength {
                structure: "AccountAddress".into(),
                expected: ACCOUNT_ADDRESS_SIZE,
                actual: bytes.len(),
            });
        }

        let address = <[u8; ACCOUNT_ADDRESS_SIZE]>::try_from(bytes)
            .map_err(|e| serde_error!("AccountAddress", e))?;

        Ok(Self(address))
    }
}

impl Serialize for AccountAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // See comment in deserialize.
        serializer.serialize_newtype_struct("AccountAddress", &self.0)
    }
}

impl<'de> Deserialize<'de> for AccountAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // In order to preserve the Serde data model and help analysis tools,
        // make sure to wrap our value in a container with the same name
        // as the original type.
        #[derive(::serde::Deserialize)]
        #[serde(rename = "AccountAddress")]
        struct Value([u8; ACCOUNT_ADDRESS_SIZE]);

        let value = Value::deserialize(deserializer)?;
        Ok(AccountAddress::new(value.0))
    }
}
