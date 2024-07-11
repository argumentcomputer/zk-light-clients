// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Signing Data
//!
//! The module contains the `SigningData` data structure which is used to sign messages in the Ethereum 2.0 network.
//! The data structure notably contains the object root and the domain to sign the message.
//!
//! # Note
//!
//! The domain bytes is actually constant for Beacon blocks on the Deneb fork. Our constant representing
//! it can be found as [`crate::types::utils::DOMAIN_BEACON_DENEB`].

use crate::crypto::error::CryptoError;
use crate::crypto::hash::HashValue;
use crate::merkle::utils::{merkle_root, DataType};
use crate::merkle::Merkleized;
use crate::types::Bytes32;

pub struct SigningData {
    object_root: Bytes32,
    domain: Bytes32,
}

impl SigningData {
    pub const fn new(object_root: Bytes32, domain: Bytes32) -> Self {
        Self {
            object_root,
            domain,
        }
    }
}

impl Merkleized for SigningData {
    fn hash_tree_root(&self) -> Result<HashValue, CryptoError> {
        let leaves: Vec<HashValue> = vec![self.object_root.into(), self.domain.into()];

        merkle_root(DataType::Struct(leaves))
    }
}
