// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use kadena_lc_core::crypto::hash::HashValue;
use kadena_lc_core::merkle::spv::Spv;
use kadena_lc_core::types::header::layer::ChainwebLayerHeader;

sphinx_zkvm::entrypoint!(main);

pub fn main() {
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let layer_headers_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    let spv_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    let expected_root_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: deserialize_inputs");
    }
    let layer_headers = ChainwebLayerHeader::deserialize_list(&layer_headers_bytes)
        .expect("Failed to deserialize layer headers");
    let spv = Spv::from_bytes(&spv_bytes).expect("Failed to deserialize SPV proof");
    let expected_root =
        HashValue::from_slice(&expected_root_bytes).expect("Failed to deserialize expected root");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: deserialize_inputs");
    }

    let (first_layer_hash, target_layer_hash, confirmation_work) =
        ChainwebLayerHeader::verify(&layer_headers).expect("Failed to verify layer headers");

    let Ok(true) = spv.verify(&expected_root) else {
        panic!("SPV proof verification failed");
    };

    let mut confirmation_work_buf: [u8; 32] = [0; 32];
    confirmation_work.to_little_endian(&mut confirmation_work_buf);
    // Confirmation cumulative work as an output
    sphinx_zkvm::io::commit(&confirmation_work_buf);

    // Base block hash as an output
    sphinx_zkvm::io::commit(first_layer_hash.as_ref());

    // Target block hash
    sphinx_zkvm::io::commit(target_layer_hash.as_ref());

    // Subject hash bytes
    sphinx_zkvm::io::commit(
        &spv.subject()
            .hash_as_leaf()
            .expect("Failed to hash subject")
            .as_ref(),
    );
}
