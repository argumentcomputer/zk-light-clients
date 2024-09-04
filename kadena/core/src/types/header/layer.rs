// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::U256;
use crate::types::error::ValidationError;
use crate::types::header::chain::KadenaHeaderRaw;
use getset::Getters;

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct ChainwebLayerHeader {
    height: u64,
    chain_headers: Vec<KadenaHeaderRaw>,
}

impl ChainwebLayerHeader {
    pub const fn new(height: u64, chain_headers: Vec<KadenaHeaderRaw>) -> Self {
        Self {
            height,
            chain_headers,
        }
    }

    pub fn produced_work(&self) -> Result<U256, ValidationError> {
        self.chain_headers
            .iter()
            .try_fold(U256::zero(), |acc, header| {
                header.produced_work().map(|work| acc + work)
            })
    }
}
