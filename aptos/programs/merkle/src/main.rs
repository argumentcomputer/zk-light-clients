#![no_main]

use aptos_lc_core::crypto::hash::HashValue;
use aptos_lc_core::merkle::proof::SparseMerkleProof;
wp1_zkvm::entrypoint!(main);

pub fn main() {
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let sparse_merkle_proof_bytes = wp1_zkvm::io::read::<Vec<u8>>();
    let key = wp1_zkvm::io::read::<[u8; 32]>();
    let leaf_value_hash = wp1_zkvm::io::read::<[u8; 32]>();
    let expected_root_hash = wp1_zkvm::io::read::<[u8; 32]>();

    let sparse_merkle_proof = SparseMerkleProof::from_bytes(&sparse_merkle_proof_bytes)
        .expect("from_bytes: could not desrialize SparseMerkleProof");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: verify_merkle_proof");
    }
    let reconstructed_root_hash = sparse_merkle_proof
        .verify_by_hash(
            HashValue::from_slice(expected_root_hash)
                .expect("expected_root_hash: could not use input to create HashValue"),
            HashValue::from_slice(key).expect("key: could not use input to create HashValue"),
            HashValue::from_slice(leaf_value_hash)
                .expect("leaf_value_hash: could not use input to create HashValue"),
        )
        .expect("verify_by_hash: could not verify proof");
    wp1_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: verify_merkle_proof");
    }
    wp1_zkvm::io::commit(reconstructed_root_hash.as_ref());
}
