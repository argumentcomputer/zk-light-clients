// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use aptos_lc_core::types::ledger_info::LedgerInfoWithSignatures;
sphinx_zkvm::entrypoint!(main);

pub fn main() {
    let ledger_info_with_sig_bytes = sphinx_zkvm::io::read::<Vec<u8>>();

    let ledger_info_with_sig = LedgerInfoWithSignatures::from_bytes(&ledger_info_with_sig_bytes)
        .expect(
            "LedgerInfoWithSignatures::from_bytes: could not create ledger info with signatures",
        );

    let ledger_info = ledger_info_with_sig.ledger_info();
    let validator_verifier = ledger_info
        .next_epoch_state()
        .expect("LedgerInfo should contain NextEpochState")
        .clone()
        .verifier;
    let agg_sig = ledger_info_with_sig.signatures();

    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_multi_signatures");
    }
    validator_verifier
        .verify_multi_signatures(&ledger_info, &agg_sig)
        .expect("verify_multi_signatures: could not verify multi signatures");
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: verify_multi_signatures");
    }
    sphinx_zkvm::io::commit(&true);
}
