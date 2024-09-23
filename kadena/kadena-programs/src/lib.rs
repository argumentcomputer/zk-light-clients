// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

pub const LONGEST_CHAIN_PROGRAM: &[u8] = include_bytes!("../artifacts/longest-chain-program");
pub const SPV_PROGRAM: &[u8] = include_bytes!("../artifacts/spv-program");

pub mod bench {
    pub const SHA512_256_PROGRAM: &[u8] =
        include_bytes!("../artifacts/benchmarks/sha512-caller-program");

    pub const BLOCK_HEADER_HASHING_PROGRAM: &[u8] =
        include_bytes!("../artifacts/benchmarks/block-header-hashing-program");
}
