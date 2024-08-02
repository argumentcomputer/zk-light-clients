// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use ethereum_lc_core::crypto::hash::keccak256_hash;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::Update;

sphinx_zkvm::entrypoint!(main);

pub fn main() {
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let store_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    let update_bytes = sphinx_zkvm::io::read::<Vec<u8>>();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }

    // Deserialize data structure
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: deserialize_light_client_store");
    }
    let mut store = LightClientStore::from_ssz_bytes(&store_bytes)
        .expect("LightClientStore::from_ssz_bytes: could not create store");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: deserialize_light_client_store");
    }

    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: deserialize_update");
    }
    let update = Update::from_ssz_bytes(&update_bytes)
        .expect("Update::from_ssz_bytes: could not create update");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: deserialize_update");
    }
    // Hash current sync committee
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: old_sync_committee_ssz_ser");
    }
    let signer_committee_bytes = store.current_sync_committee().to_ssz_bytes();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: old_sync_committee_ssz_ser");
    }
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: hash_current_sync_committee");
    }
    let signer_sync_committee_hash = keccak256_hash(&signer_committee_bytes)
        .expect("LightClientStore::current_sync_committee: could not hash committee");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: hash_current_sync_committee");
    }

    // Process update
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: process_update");
    }
    store
        .process_light_client_update(&update)
        .expect("LightClientStore::process_light_client_update: could not process update");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: process_update");
    }
    // Hash updated sync committee
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: new_sync_committee_ssz_ser");
    }
    let new_sync_committee_bytes = store.current_sync_committee().to_ssz_bytes();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: new_sync_committee_ssz_ser");
    }
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: hash_new_sync_committee");
    }
    let updated_sync_committee_hash = keccak256_hash(&new_sync_committee_bytes)
        .expect("LightClientStore::current_sync_committee: could not hash committee after processing update");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: hash_new_sync_committee");
    }
    let next_sync_committee_hash = keccak256_hash(&store.next_sync_committee().as_ref().expect("Store should have a next sync committee after processing update").to_ssz_bytes())
        .expect("LightClientStore::current_sync_committee: could not hash committee after processing update");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: hash_new_sync_committee");
    }
    // Commit the signer hash, the current and next sync committee hashes, and the block height
    sphinx_zkvm::io::commit(update.finalized_header().beacon().slot());
    sphinx_zkvm::io::commit(&signer_sync_committee_hash.hash());
    sphinx_zkvm::io::commit(&updated_sync_committee_hash.hash());
    sphinx_zkvm::io::commit(&next_sync_committee_hash.hash());
}
