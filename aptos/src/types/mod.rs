// SPDX-License-Identifier: Apache-2.0, MIT
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use test_strategy::Arbitrary;

pub mod block_info;
pub mod epoch_state;
pub mod error;
pub mod ledger_info;
pub mod trusted_state;
mod validator;
pub mod waypoint;

pub type Round = u64;
pub type Version = u64;

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Copy, Arbitrary)]
pub struct AccountAddress([u8; 32]);

impl AccountAddress {
    pub const fn new(address: [u8; 32]) -> Self {
        Self(address)
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
        struct Value([u8; 32]);

        let value = Value::deserialize(deserializer)?;
        Ok(AccountAddress::new(value.0))
    }
}
