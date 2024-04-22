#![no_main]

use aptos_lc_core::crypto::sig::AggregateSignature;
use aptos_lc_core::types::ledger_info::{
    LedgerInfo, AGG_SIGNATURE_LEN, LEDGER_INFO_LEN, OFFSET_LEDGER_INFO, OFFSET_SIGNATURE,
};
use std::hint::black_box;
wp1_zkvm::entrypoint!(main);

pub fn main() {
    let ledger_info_with_sig_bytes = wp1_zkvm::io::read::<Vec<u8>>();

    // Extract bytes from the ledger info for given offsets and length
    let ledger_info_bytes = extract_bytes(
        &ledger_info_with_sig_bytes,
        OFFSET_LEDGER_INFO,
        LEDGER_INFO_LEN,
    );
    let signature_bytes = extract_bytes(
        &ledger_info_with_sig_bytes,
        OFFSET_SIGNATURE,
        AGG_SIGNATURE_LEN,
    );

    let ledger_info = black_box(LedgerInfo::from_bytes(black_box(&ledger_info_bytes)))
        .expect("LedgerInfo::from_bytes: could not create ledger info");
    let validator_verifier = ledger_info
        .next_epoch_state()
        .expect("LedgerInfo should contain NextEpochState")
        .clone()
        .verifier;
    let agg_sig = black_box(AggregateSignature::from_bytes(black_box(&signature_bytes)))
        .expect("AggregateSignature::from_bytes: could not create aggregate signature");

    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_multi_signatures");
    }
    validator_verifier
        .verify_multi_signatures(&ledger_info, &agg_sig)
        .expect("verify_multi_signatures: could not verify multi signatures");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: verify_multi_signatures");
    }
    wp1_zkvm::io::commit(&true);
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
