// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! This module MUST be updated if the chain graph degree changes.
//!
//! A graph degree change also requires a change in the following methods:
//! - [`crate::types::header::chain::KadenaHeaderRaw::header_root`]
//! - [`crate::types::header::layer::ChainwebLayerHeader::verify`]
//!
//!
//! The fact that this is a constant means that the code in this and any derived
//! module can only be used with headers which have the same chain graph degree.

/// The degree of the chain graph. This the number of adjacent parents for
/// each block header.
pub const GRAPH_DEGREE: usize = 3;
pub const GRAPH_ORDER: usize = 20;

pub type TwentyChainGraphType = [[u32; GRAPH_DEGREE]; GRAPH_ORDER];

/// The chain graph for the 20-chain network, sorted by chain ID, then
/// from the lowest chain ID to the highest parent chain ID.
pub const CHAIN_GRAPH: TwentyChainGraphType = [
    [5, 10, 15],
    [6, 11, 16],
    [7, 12, 17],
    [8, 13, 18],
    [9, 14, 19],
    [0, 7, 8],
    [1, 8, 9],
    [2, 5, 9],
    [3, 5, 6],
    [4, 6, 7],
    [0, 11, 19],
    [1, 10, 12],
    [2, 11, 13],
    [3, 12, 14],
    [4, 13, 15],
    [0, 14, 16],
    [1, 15, 17],
    [2, 16, 18],
    [3, 17, 19],
    [4, 10, 18],
];
