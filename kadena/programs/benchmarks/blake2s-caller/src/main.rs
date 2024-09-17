// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

#![no_main]
sphinx_zkvm::entrypoint!(main);

use blake2::{Blake2s256, Digest};

pub fn main() {
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let preimage = sphinx_zkvm::io::read::<Vec<u8>>();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }

    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: hashing");
    }

    let mut hasher = Blake2s256::new();

    hasher.update(preimage);

    let output = hasher.finalize();

    let mut ret = [0u8; 32];
    ret.copy_from_slice(&output);

    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: hashing");
    }

    sphinx_zkvm::io::commit::<[u8; 32]>(&ret);
}
