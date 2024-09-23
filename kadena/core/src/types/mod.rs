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
