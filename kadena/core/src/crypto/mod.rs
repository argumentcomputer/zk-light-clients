// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use uint::construct_uint;

pub mod hash;

pub const U256_BYTES_LENGTH: usize = 32;

construct_uint! {
    pub struct U256(4);
}
