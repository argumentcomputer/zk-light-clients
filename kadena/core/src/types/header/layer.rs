// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::U256;
use crate::types::error::ValidationError;
use crate::types::header::chain::KadenaHeaderRaw;
use getset::Getters;

/// A layer header for a Chainweb network. It contains the height of the layer and the headers of
/// all the chains in the Chainweb network at the given height.
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct ChainwebLayerHeader {
    height: u64,
    chain_headers: Vec<KadenaHeaderRaw>,
}

impl ChainwebLayerHeader {
    /// Create a new `ChainwebLayerHeader` with the given height and chain headers.
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the layer.
    /// * `chain_headers` - The headers of all the chains in the Chainweb network at the given height.
    ///
    /// # Returns
    ///
    /// A new `ChainwebLayerHeader`.
    pub const fn new(height: u64, chain_headers: Vec<KadenaHeaderRaw>) -> Self {
        Self {
            height,
            chain_headers,
        }
    }

    /// Get the total amount of work produced by all the chains in the layer.
    ///
    /// # Returns
    ///
    /// The total amount of work produced by all the chains in the layer.
    pub fn produced_work(&self) -> Result<U256, ValidationError> {
        self.chain_headers
            .iter()
            .try_fold(U256::zero(), |acc, header| {
                header.produced_work().map(|work| acc + work)
            })
    }
}
