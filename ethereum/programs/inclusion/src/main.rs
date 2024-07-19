// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use ethereum_lc_core::crypto::hash::keccak256_hash;
use ethereum_lc_core::merkle::storage_proofs::EIP1186Proof;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::Update;

sphinx_zkvm::entrypoint!(main);

pub fn main() {
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let store_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    let update_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    let eip1186_proof_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }

    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: deserialize_inputs");
    }
    let store = LightClientStore::from_ssz_bytes(&store_bytes)
        .expect("LightClientStore::from_ssz_bytes: could not create store");
    let update = Update::from_ssz_bytes(&update_bytes)
        .expect("Update::from_ssz_bytes: could not create update");
    let eip1186_proof = EIP1186Proof::from_ssz_bytes(&eip1186_proof_bytes)
        .expect("EIP1186Proof::from_ssz_bytes: could not create proof");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: deserialize_inputs");
    }

    // Validate the received update
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: validate_update");
    }
    store
        .validate_light_client_update(&update)
        .expect("validate_light_client_update: could not validate update");
    sphinx_zkvm::precompiles::unconstrained! {
            println!("cycle-tracker-end: validate_update");
    }

    // Verify proof against finalized state root
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_proof");
    }
    eip1186_proof
        .verify(update.finalized_header().execution().state_root())
        .expect("verify: could not verify proof");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: verify_proof");
    }

    // Output the signers sync committee hash, the attested block number, the hash of address + storage keys
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: output");
    }
    let sync_committee_hash = keccak256_hash(&store.current_sync_committee().to_ssz_bytes())
        .expect("LightClientStore::current_sync_committee: could not hash committee after inclusion proving");
    sphinx_zkvm::io::commit(update.attested_header().beacon().slot());
    sphinx_zkvm::io::commit(sync_committee_hash.as_ref());
    sphinx_zkvm::io::commit(
        eip1186_proof
            .key_hash()
            .expect("EIP1186Proof::key_hash: could not get key hash")
            .as_ref(),
    );
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: output");
    }
}
