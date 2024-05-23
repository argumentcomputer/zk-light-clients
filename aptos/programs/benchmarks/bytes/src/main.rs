#![no_main]

use aptos_lc_core::crypto::sig::AggregateSignature;
use aptos_lc_core::types::ledger_info::{
    LedgerInfo, AGG_SIGNATURE_LEN, LEDGER_INFO_NEW_EPOCH_LEN, OFFSET_LEDGER_INFO, OFFSET_SIGNATURE,
};
use std::hint::black_box;
wp1_zkvm::entrypoint!(main);

pub fn main() {
    let ledger_info_with_sig_bytes = wp1_zkvm::io::read::<Vec<u8>>();

    // Extract bytes from the ledger info for given offsets and length.
    let ledger_info_bytes = extract_bytes(
        &ledger_info_with_sig_bytes,
        OFFSET_LEDGER_INFO,
        LEDGER_INFO_NEW_EPOCH_LEN,
    );
    let signature_bytes = extract_bytes(
        &ledger_info_with_sig_bytes,
        OFFSET_SIGNATURE,
        AGG_SIGNATURE_LEN,
    );

    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: ledger_info_from_bytes");
    }
    let ledger_info = black_box(LedgerInfo::from_bytes(black_box(&ledger_info_bytes)))
        .expect("LedgerInfo::from_bytes: could not create ledger info");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: ledger_info_from_bytes");
    }
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: validator_verifier");
    }
    let validator_verifier = ledger_info
        .next_epoch_state()
        .expect("LedgerInfo should contain NextEpochState")
        .clone()
        .verifier;
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: validator_verifier");
    }
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: agg_sig_from_bytes");
    }
    let agg_sig = black_box(AggregateSignature::from_bytes(black_box(&signature_bytes)))
        .expect("AggregateSignature::from_bytes: could not create aggregate signature");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: agg_sig_from_bytes");
    }

    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: validator_verifier_to_bytes");
    }
    let validator_verifier_bytes = validator_verifier.to_bytes();
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: validator_verifier_to_bytes");
    }
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: ledger_info_to_bytes");
    }
    let ledger_info_bytes = ledger_info.to_bytes();
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: ledger_info_to_bytes");
    }
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: agg_sig_to_bytes");
    }
    let agg_sig_bytes = agg_sig.to_bytes();
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: agg_sig_to_bytes");
    }

    wp1_zkvm::io::commit(&validator_verifier_bytes);
    wp1_zkvm::io::commit(&ledger_info_bytes);
    wp1_zkvm::io::commit(&agg_sig_bytes);
}

#[wp1_derive::cycle_tracker]
fn extract_bytes(bytes: &[u8], offset: usize, len: usize) -> Vec<u8> {
    bytes
        .iter()
        .skip(offset)
        .take(len)
        .copied()
        .collect::<Vec<u8>>()
}
