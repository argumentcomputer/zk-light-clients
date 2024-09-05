// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

pub mod blake2;
pub mod sha512;

/// Size in bytes of a digest in the context of the Kadena chain.
pub const DIGEST_BYTES_LENGTH: usize = 32;
