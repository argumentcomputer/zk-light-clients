// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::HASH_LENGTH;
use crate::types::error::TypesError;
use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod block_info;
pub mod epoch_state;
pub mod error;
pub mod ledger_info;
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
        let address = <[u8; ACCOUNT_ADDRESS_SIZE]>::try_from(bytes).map_err(|e| {
            TypesError::DeserializationError {
                structure: String::from("AccountAddress"),
                source: e.into(),
            }
        })?;
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
