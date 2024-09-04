// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

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
}
