// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

#![no_main]

sphinx_zkvm::entrypoint!(main);

pub fn main() {
    let _ = 1 + 2;
}
