#![no_main]

use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::types::trusted_state::{EpochChangeProof, TrustedState, TrustedStateChange};

wp1_zkvm::entrypoint!(main);

pub fn main() {
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let trusted_state_bytes = wp1_zkvm::io::read::<Vec<u8>>();
    let epoch_change_proof = wp1_zkvm::io::read::<Vec<u8>>();
    let previous_validator_verifier_hash = wp1_zkvm::io::read::<Vec<u8>>();
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }

    // Deserialize Rust structures
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: deserialize_trusted_state");
    }
    let trusted_state = TrustedState::from_bytes(&trusted_state_bytes)
        .expect("TrustedState::from_bytes: could not create trusted state");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: deserialize_trusted_state");
    }
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: deserialize_epoch_change_proof");
    }
    let epoch_change_proof = EpochChangeProof::from_bytes(&epoch_change_proof)
        .expect("EpochChangeProof::from_bytes: could not create epoch change proof");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: deserialize_epoch_change_proof");
    }
    // Check if the received validator set for the current epoch is the one we produced a proof for previously?
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: hash_comparison");
    }
    let previous_validator_verifier_hash = HashValue::from_slice(previous_validator_verifier_hash)
        .expect("previous_validator_verifier_hash: Could not create hash value from bytes");
    let prev_epoch_validator_verifier_hash = match &trusted_state {
        TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash(),
        _ => panic!("Expected epoch change for current trusted state"),
    };
    assert_eq!(
        prev_epoch_validator_verifier_hash, previous_validator_verifier_hash,
        "Validator verifier hash mismatch with previously known one"
    );
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: hash_comparison");
    }

    // Verify and ratchet the trusted state
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_and_ratchet");
    }
    let trusted_state_change = trusted_state
        .verify_and_ratchet_inner(&epoch_change_proof)
        .expect("TrustedState::verify_and_ratchet_inner: could not ratchet");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: verify_and_ratchet");
    }

    // Extract new trusted state
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: validator_verifier_hash");
    }
    let validator_verifier_hash = match trusted_state_change {
        TrustedStateChange::Epoch {
            latest_epoch_change_li,
            ..
        } => latest_epoch_change_li
            .ledger_info()
            .next_epoch_state()
            .expect("Expected epoch state")
            .verifier()
            .hash(),
        _ => panic!("Expected epoch change"),
    };
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: validator_verifier_hash");
    }

    // Hash it and pass the hash as the now trusted state
    wp1_zkvm::io::commit(validator_verifier_hash.as_ref());
}
