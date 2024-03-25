// SPDX-License-Identifier: Apache-2.0, MIT
use crate::merkle::proof::SparseMerkleProof;
use crate::types::ledger_info::LedgerInfoWithSignatures;
use crate::unit_tests::aptos::wrapper::AptosWrapper;

pub mod wrapper;

#[test]
pub fn test_serde_ledger_info_w_sig() {
    let mut aptos_wrapper = AptosWrapper::new(4, 1);

    aptos_wrapper.generate_traffic();

    let intern_li: LedgerInfoWithSignatures =
        bcs::from_bytes(&aptos_wrapper.get_latest_li_bytes().unwrap()).unwrap();

    let intern_li_bytes = bcs::to_bytes(&intern_li).unwrap();

    let og_li: aptos_types::ledger_info::LedgerInfoWithSignatures =
        bcs::from_bytes(&intern_li_bytes).unwrap();

    assert_eq!(og_li, aptos_wrapper.get_latest_li().unwrap());
}

#[test]
pub fn test_serde_sparse_merkle_proof() {
    let mut aptos_wrapper = AptosWrapper::new(4, 1);

    aptos_wrapper.generate_traffic();

    let proof_assets = aptos_wrapper.get_latest_proof_account(0).unwrap();

    let intern_proof: SparseMerkleProof =
        bcs::from_bytes(&bcs::to_bytes(proof_assets.state_proof()).unwrap()).unwrap();

    let intern_proof_bytes = bcs::to_bytes(&intern_proof).unwrap();

    let og_proof: aptos_types::proof::SparseMerkleProof =
        bcs::from_bytes(&intern_proof_bytes).unwrap();

    assert_eq!(og_proof, proof_assets.state_proof().clone());
}
