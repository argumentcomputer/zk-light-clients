// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

pub mod adjacent;
pub mod error;
pub mod graph;
pub mod header;
pub mod utils;

/// Size in bytes of a u16.
pub const U16_BYTES_LENGTH: usize = 2;
/// Size in bytes of a u32.
pub const U32_BYTES_LENGTH: usize = 4;
/// Size in bytes of a u64.
pub const U64_BYTES_LENGTH: usize = 8;
/// Target block time in micro seconds.
pub const BLOCK_DELAY: u64 = 30_000_000;
//. Number of blocks in an Epoch
pub const WINDOW_WIDTH: u64 = 120;
pub const EPOCH_LENGTH: u64 = 120;
