// SPDX-License-Identifier: Apache-2.0, MIT
pub mod wrapper;

#[cfg(test)]
mod test {
    use crate::aptos_test_utils::wrapper::AptosWrapper;
    use crate::merkle::proof::SparseMerkleProof;
    use crate::types::error::VerifyError;
    use crate::types::ledger_info::LedgerInfoWithSignatures;
    use crate::types::validator::{ValidatorConsensusInfo, ValidatorVerifier};
    use crate::types::AccountAddress;
    use crate::NBR_VALIDATORS;
    use bls12_381::{G1Affine, G1Projective};
    use std::ops::Add;

    #[test]
    pub fn test_serde_ledger_info_w_sig() {
        let mut aptos_wrapper = AptosWrapper::new(4, NBR_VALIDATORS);

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

    #[test]
    pub fn test_sig_verify() {
        let mut aptos_wrapper = AptosWrapper::new(4, 10);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let intern_li: LedgerInfoWithSignatures =
            bcs::from_bytes(&aptos_wrapper.get_latest_li_bytes().unwrap()).unwrap();
        let validator_verifier: ValidatorVerifier = intern_li
            .ledger_info()
            .next_epoch_state()
            .unwrap()
            .verifier
            .clone();
        intern_li.verify_signatures(&validator_verifier).unwrap();

        // Check with fake validator verifier
        let mut validator_info = validator_verifier.validator_infos().clone();
        let address = AccountAddress::new([0; 32]);
        let key = crate::crypto::sig::PublicKey::try_from(
            G1Affine::from(G1Projective::generator().add(G1Projective::generator()))
                .to_compressed()
                .as_slice(),
        )
        .unwrap();
        validator_info[0] = ValidatorConsensusInfo::new(address, key, 500);

        let res = intern_li.verify_signatures(&ValidatorVerifier::new(validator_info));
        assert!(res.is_err());

        assert_eq!(res.err().unwrap(), VerifyError::InvalidMultiSignature);
    }
}
