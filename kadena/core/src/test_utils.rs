// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

pub const COMPACT_HEADER_PATH: &str = "../test-assets/compact.json";

pub fn get_compact_headers_bytes() -> Vec<u8> {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let test_asset_path = root_path.join(COMPACT_HEADER_PATH);

    fs::read(test_asset_path).unwrap()
}
