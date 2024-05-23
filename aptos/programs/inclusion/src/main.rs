#![no_main]

use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::merkle::sparse_proof::SparseMerkleProof;
use aptos_lc_core::merkle::transaction_proof::TransactionAccumulatorProof;
use aptos_lc_core::types::ledger_info::LedgerInfoWithSignatures;
use aptos_lc_core::types::ledger_info::LEDGER_INFO_NEW_BLOCK_HEIGHT_LEN;
use aptos_lc_core::types::transaction::TransactionInfo;
use aptos_lc_core::types::validator::ValidatorVerifier;

wp1_zkvm::entrypoint!(main);

pub fn main() {
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    // Get inputs for account inclusion
    let sparse_merkle_proof_bytes = wp1_zkvm::io::read::<Vec<u8>>();
    let key = wp1_zkvm::io::read::<[u8; 32]>();
    let leaf_value_hash = wp1_zkvm::io::read::<[u8; 32]>();

    // Get inputs for tx inclusion
    let transaction_bytes = wp1_zkvm::io::read::<Vec<u8>>();
    let transaction_index = wp1_zkvm::io::read::<u64>();
    let transaction_proof = wp1_zkvm::io::read::<Vec<u8>>();
    let ledger_info_bytes = wp1_zkvm::io::read::<Vec<u8>>();

    // Latest verified validator verifier &  hash
    let verified_validator_verifier = wp1_zkvm::io::read::<Vec<u8>>();
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }

    // Deserialize Validator Verifier
    let validator_verifier = ValidatorVerifier::from_bytes(&verified_validator_verifier)
        .expect("validator_verifier: could not create ValidatorVerifier from bytes");

    // Verify transaction inclusion in the LedgerInfoWithSignatures
    let transaction = TransactionInfo::from_bytes(&transaction_bytes)
        .expect("from_bytes: could not deserialize TransactionInfo");
    let transaction_hash = transaction.hash();
    let transaction_proof = TransactionAccumulatorProof::from_bytes(&transaction_proof)
        .expect("from_bytes: could not deserialize TransactionAccumulatorProof");
    let latest_li = LedgerInfoWithSignatures::from_bytes::<LEDGER_INFO_NEW_BLOCK_HEIGHT_LEN>(
        &ledger_info_bytes,
    )
    .expect("from_bytes: could not deserialize LedgerInfo");

    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_transaction_inclusion");
    }
    let expected_root_hash = HashValue::from_slice(
        latest_li
            .ledger_info()
            .transaction_accumulator_hash()
            .as_ref(),
    )
    .unwrap();
    transaction_proof
        .verify(expected_root_hash, transaction_hash, transaction_index)
        .expect("verify: could not verify proof");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: verify_transaction_inclusion");
    }

    // Check signature
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_signature");
    }
    latest_li
        .verify_signatures(&validator_verifier)
        .expect("verify_signatures: could not verify signatures");
    wp1_zkvm::precompiles::unconstrained! {
                    println!("cycle-tracker-end: verify_signature");
    }
    // Verify account inclusion in the SparseMerkleTree
    let sparse_merkle_proof = SparseMerkleProof::from_bytes(&sparse_merkle_proof_bytes)
        .expect("from_bytes: could not deserialize SparseMerkleProof");

    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_merkle_proof");
    }
    let sparse_expected_root_hash = transaction
        .state_checkpoint()
        .expect("state_checkpoint: could not get state checkpoint");
    let reconstructed_root_hash = sparse_merkle_proof
        .verify_by_hash(
            sparse_expected_root_hash,
            HashValue::from_slice(key).expect("key: could not use input to create HashValue"),
            HashValue::from_slice(leaf_value_hash)
                .expect("leaf_value_hash: could not use input to create HashValue"),
        )
        .expect("verify_by_hash: could not verify proof");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: verify_merkle_proof");
    }

    // Commit the validator verifier hash
    wp1_zkvm::io::commit(validator_verifier.hash().as_ref());

    // Commit the state root hash
    wp1_zkvm::io::commit(reconstructed_root_hash.as_ref());
}
