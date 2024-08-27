// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

pub const BLOCK_HEADER_HASHING_PROGRAM: &[u8] =
    include_bytes!("../artifacts/block-header-hashing-program");

pub mod bench {
    pub const SHA512_256_PROGRAM: &[u8] =
        include_bytes!("../artifacts/benchmarks/sha512-caller-program");
}
