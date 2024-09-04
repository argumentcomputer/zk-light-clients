// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

pub mod adjacent;
pub mod error;
pub mod header;
pub mod utils;

// Tag values can be found here:
// https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function
pub const CHAIN_ID_TAG: u16 = 0x0002;
pub const BLOCK_HEIGHT_TAG: u16 = 0x0003;
pub const BLOCK_WEIGHT_TAG: u16 = 0x0004;
pub const FEATURE_FLAGS_TAG: u16 = 0x0006;
pub const BLOCK_CREATION_TIME_TAG: u16 = 0x0007;
pub const CHAINWEB_VERSION_TAG: u16 = 0x0008;
pub const HASH_TARGET_TAG: u16 = 0x0011;
pub const EPOCH_START_TIME_TAG: u16 = 0x0019;
pub const BLOCK_NONCE_TAG: u16 = 0x0020;

pub const U32_BYTES_LENGTH: usize = 4;
pub const U64_BYTES_LENGTH: usize = 8;
