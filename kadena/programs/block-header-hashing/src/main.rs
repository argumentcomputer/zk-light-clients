// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use kadena_lc_core::{header_root, KadenaHeaderRaw};

sphinx_zkvm::entrypoint!(main);

pub fn main() {
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let header_bytes_base64 = sphinx_zkvm::io::read::<Vec<u8>>();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: deserialize_inputs");
    }
    let header = KadenaHeaderRaw::from_base64(&header_bytes_base64);
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: deserialize_inputs");
    }
    let actual = header_root(&header);
    assert_eq!(header.hash().to_vec(), actual);
    sphinx_zkvm::io::commit(&actual);
}
