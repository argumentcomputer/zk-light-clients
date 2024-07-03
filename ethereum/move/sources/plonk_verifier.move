module plonk_verifier_addr::plonk_verifier {
    use std::vector;
    use std::hash::{ sha2_256 };
    use plonk_verifier_addr::utilities::{append_constant, bytes_to_uint256};
    #[test_only]
    use plonk_verifier_addr::utilities::{get_proof, get_public_inputs};
    use std::vector::length;

    // TODO: cleanup following constants as some of them could be unnecessary in Move verifier
    const R_MOD: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    const R_MOD_MINUS_ONE: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    const P_MOD: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    const G2_SRS_0_X_0: u256 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2;
    const G2_SRS_0_X_1: u256 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed;
    const G2_SRS_0_Y_0: u256 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b;
    const G2_SRS_0_Y_1: u256 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa;
    const G2_SRS_1_X_0: u256 = 0x22f1acbb03c4508760c2430af35865e7cdf9f3eb1224504fdcc3708ddb954a48;
    const G2_SRS_1_X_1: u256 = 0x2a344fad01c2ed0ed73142ae1752429eaea515c6f3f6b941103cc21c2308e1cb;
    const G2_SRS_1_Y_0: u256 = 0x159f15b842ba9c8449aa3268f981010d4c7142e5193473d80b464e964845c3f8;
    const G2_SRS_1_Y_1: u256 = 0x0efd30ac7b6f8d0d3ccbc2207587c2acbad1532dc0293f0d034cf8258cd428b3;
    const G1_SRS_X: u256 = 0x1fa4be93b5e7f7e674d5059b63554fab99638b304ed8310e9fa44c281ac9b03b;
    const G1_SRS_Y: u256 = 0x1a01ae7fac6228e39d3cb5a5e71fd31160f3241e79a5f48ffb3737e6c389b721;
    // ----------------------- vk ---------------------
    const VK_NB_PUBLIC_INPUTS: u64 = 2;
    const VK_DOMAIN_SIZE: u256 = 67108864;
    const VK_INV_DOMAIN_SIZE: u256 = 0x30644e66c81e03716be83b486d6feabcc7ddd0fe6cbf5e72d585d142f7829b05;
    const VK_OMEGA: u256 = 0x1067569af1ff73b20113eff9b8d89d4a605b52b63d68f9ae1c79bd572f4e9212;
    const VK_QL_COM_X: u256 = 0x291f93471379f3bf591fdbfe309bfe7a40269d6427b1aa1a8b8de960d96775a8;
    const VK_QL_COM_Y: u256 = 0x2283bc4ce9b8918045e93744d83fca3414ff664d225b765162c1aa94fbe55e1c;
    const VK_QR_COM_X: u256 = 0x04294a9de8e6bc370d5f036314c4705b434aa4f1b937cc35e6a767972829184c;
    const VK_QR_COM_Y: u256 = 0x01d83e7ef2d621f3edac2a4d5a930b3b5660854ef8217ee68932455e32fa5ec2;
    const VK_QM_COM_X: u256 = 0x2601143f3b897c27215a4353e2f49cf286f3a62e6829993ff5ba4c9b936f9f95;
    const VK_QM_COM_Y: u256 = 0x2f879a9b7806fda982182f42e4c897ecddfe2c7162a6512e5eb7b0eb6f521008;
    const VK_QO_COM_X: u256 = 0x07e1f52079636bee266de2c3c06d498545baf9918b54a44885e6f4cb63a6d47c;
    const VK_QO_COM_Y: u256 = 0x06068ad3520d70299638b2dba0242509254ab76f384031b47050d612a13fc895;
    const VK_QK_COM_X: u256 = 0x0cbf77bfb1482575e8fb885c67f88094020d86a77f4fa844589a7d332574a537;
    const VK_QK_COM_Y: u256 = 0x1d9db7e100affcec0f7e75af2bfa7216f450df1950b94fff7fee2795cc0a7dac;
    const VK_S1_COM_X: u256 = 0x073a45a1ce7d752ff0ed055b7ab0936aa8466c5ed136d92489ccf2ad067fbfb6;
    const VK_S1_COM_Y: u256 = 0x086bbe0f9d3160b2fe7844ae9483e6a9c02727d51acb6b555f65425a743de8d5;
    const VK_S2_COM_X: u256 = 0x2cb45f95eebb782301c335f57956c6ddd6f467183834fd1e01b1299f490826be;
    const VK_S2_COM_Y: u256 = 0x08195b6fd528afe6dc76691dc464f17de6f01b133291fd7023d3fddf2f67dc28;
    const VK_S3_COM_X: u256 = 0x1c76f451ec46bd2189516ef80c4cb09c5cdbbfa4e93a9847f44455d15e911080;
    const VK_S3_COM_Y: u256 = 0x0f6957bf727f83b077b262c8ec3060b68389a4b6185fd0ed3e4bf0a685ea6eed;
    const VK_COSET_SHIFT: u256 = 5;
    const VK_QCP_0_X: u256 = 0x237f7ac20e4012ea653cdfd8fbabd4741c883dc784d31ef04005b398beebe5e3;
    const VK_QCP_0_Y: u256 = 0x0525090d2e5e3c446a811ba313f3425326375032a51d287315e681f8bd886694;
    const VK_INDEX_COMMIT_API_0: u256 = 0x0000000000000000000000000000000000000000000000000000000001bdf707;
    const VK_NB_CUSTOM_GATES: u64 = 1;
    // ------------------------------------------------
    // offset proof
    const PROOF_L_COM_X: u256 = 0x0;
    const PROOF_L_COM_Y: u256 = 0x20;
    const PROOF_R_COM_X: u256 = 0x40;
    const PROOF_R_COM_Y: u256 = 0x60;
    const PROOF_O_COM_X: u256 = 0x80;
    const PROOF_O_COM_Y: u256 = 0xa0;
    // h = h_0 + x^{n+2}h_1 + x^{2(n+2)}h_2
    const PROOF_H_0_X: u256 = 0xc0;
    const PROOF_H_0_Y: u256 = 0xe0;
    const PROOF_H_1_X: u256 = 0x100;
    const PROOF_H_1_Y: u256 = 0x120;
    const PROOF_H_2_X: u256 = 0x140;
    const PROOF_H_2_Y: u256 = 0x160;
    // wire values at zeta
    const PROOF_L_AT_ZETA: u256 = 0x180;
    const PROOF_R_AT_ZETA: u256 = 0x1a0;
    const PROOF_O_AT_ZETA: u256 = 0x1c0;
    // S1(zeta),S2(zeta)
    const PROOF_S1_AT_ZETA: u256 = 0x1e0;
    const PROOF_S2_AT_ZETA: u256 = 0x200;
    // [Z]
    const PROOF_GRAND_PRODUCT_COMMITMENT_X: u256 = 0x220;
    const PROOF_GRAND_PRODUCT_COMMITMENT_Y: u256 = 0x240;
    const PROOF_GRAND_PRODUCT_AT_ZETA_OMEGA: u256 = 0x260; // z(w*zeta)
    // Folded proof for the opening of linearised poly, l, r, o, s_1, s_2, qcp
    const PROOF_BATCH_OPENING_AT_ZETA_X: u256 = 0x280;
    const PROOF_BATCH_OPENING_AT_ZETA_Y: u256 = 0x2a0;
    const PROOF_OPENING_AT_ZETA_OMEGA_X: u256 = 0x2c0;
    const PROOF_OPENING_AT_ZETA_OMEGA_Y: u256 = 0x2e0;
    const PROOF_OPENING_QCP_AT_ZETA: u256 = 0x300;
    const PROOF_BSB_COMMITMENTS: u256 = 0x320;
    // -> next part of proof is
    // [ openings_selector_commits || commitments_wires_commit_api]
    // -------- offset state
    // challenges to check the claimed quotient
    const STATE_ALPHA: u256 = 0x0;
    const STATE_BETA: u256 = 0x20;
    const STATE_GAMMA: u256 = 0x40;
    const STATE_ZETA: u256 = 0x60;
    const STATE_ALPHA_SQUARE_LAGRANGE_0: u256 = 0x80;
    const STATE_FOLDED_H_X: u256 = 0xa0;
    const STATE_FOLDED_H_Y: u256 = 0xc0;
    const STATE_LINEARISED_POLYNOMIAL_X: u256 = 0xe0;
    const STATE_LINEARISED_POLYNOMIAL_Y: u256 = 0x100;
    const STATE_OPENING_LINEARISED_POLYNOMIAL_ZETA: u256 = 0x120;
    const STATE_FOLDED_CLAIMED_VALUES: u256 = 0x140; // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
    const STATE_FOLDED_DIGESTS_X: u256 = 0x160; // folded digests of H, linearised poly, l, r, o, s_1, s_2, qcp
    const STATE_FOLDED_DIGESTS_Y: u256 = 0x180;
    const STATE_PI: u256 = 0x1a0;
    const STATE_ZETA_POWER_N_MINUS_ONE: u256 = 0x1c0;
    const STATE_GAMMA_KZG: u256 = 0x1e0;
    const STATE_SUCCESS: u256 = 0x200;
    const STATE_CHECK_VAR: u256 = 0x220; // /!\ this slot is used for debugging only
    const STATE_LAST_MEM: u256 = 0x240;
    // -------- utils (for Fiat Shamir)
    const FS_ALPHA: u256 = 0x616C706861; // "alpha"
    const FS_BETA: u256 = 0x62657461; // "beta"
    const FS_GAMMA: u256 = 0x67616d6d61; // "gamma"
    const FS_ZETA: u256 = 0x7a657461; // "zeta"
    const FS_GAMMA_KZG: u256 = 0x67616d6d61; // "gamma"
    // -------- errors
    const ERROR_STRING_ID: u256 = 0x08c379a000000000000000000000000000000000000000000000000000000000; // selector for function Error(string)
    // -------- utils (for hash_fr)
    const HASH_FR_BB: u256 = 0x0000000000000000000000000000000100000000000000000000000000000000; // 2**128
    const HASH_FR_ZERO_UINT256: u256 = 0;
    const HASH_FR_LEN_IN_BYTES: u8 = 48;
    const HASH_FR_SIZE_DOMAIN: u8 = 11;
    const HASH_FR_ONE: u8 = 1;
    const HASH_FR_TWO: u8 = 2;
    // -------- precompiles
    const MOD_EXP: u8 = 0x5;
    const EC_ADD: u8 = 0x6;
    const EC_MUL: u8 = 0x7;
    const EC_PAIR: u8 = 0x8;

    // TODO: add function for computing this digest based on the SphinxVerifier.sol contract
    const SphinxPublicValuesHash: u256 = 0x1b73d6e73d3224150622f22a8c18740efc94af34d45500eaf658a389935513ad;
    const SphinxInclusionProofVk: u256 = 0x00edc477759b49c9f16fa0fae93b11dcde295121eda80472196c13cf4b6d079f;


    const ERROR_NB_PUBLIC_INPUTS: u64 = 1001;
    const ERROR_INPUTS_SIZE: u64 = 1002;
    const ERROR_PROOF_SIZE: u64 = 1003;
    const ERROR_PROOF_OPENING_SIZE: u64 = 1004;

    #[test]
    public fun test_verify() {
        let proof = get_proof();
        let public_inputs = get_public_inputs();
        verify(proof, public_inputs);
    }

    public fun verify(proof: vector<u256>, public_inputs: vector<u256>) {
        // check number of public inputs
        assert!(length(&public_inputs) == VK_NB_PUBLIC_INPUTS, ERROR_NB_PUBLIC_INPUTS);

        // check size of the public_inputs
        let i = 0;
        while(i < VK_NB_PUBLIC_INPUTS) {
            assert!(R_MOD_MINUS_ONE > (*vector::borrow(&public_inputs, i)), ERROR_INPUTS_SIZE);
            i = i + 1
        };

        // check proof size
        assert!(length(&proof) * 32 == VK_NB_CUSTOM_GATES * 96 + 768, ERROR_PROOF_SIZE);

        // check size of proof openings
        i = 0;
        while(i < length(&proof)) {
            assert!(R_MOD_MINUS_ONE > (*vector::borrow(&proof, i)), ERROR_PROOF_OPENING_SIZE);
            i = i + 1
        };

        let vk = *vector::borrow(&public_inputs, 0);
        let public_inputs_digest = *vector::borrow(&public_inputs, 1);

        let gamma = derive_gamma(proof, vk, public_inputs_digest);
        let beta = derive_beta(gamma);
        let alpha = derive_alpha(proof, beta);
        let zeta = derive_zeta(proof, alpha);

        assert!(zeta == 0x16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a, 1);

        // TODO adding rest of verification logic ...
    }

    public fun derive_gamma(proof: vector<u256>, vk: u256, public_inputs_digest: u256): u256 {
        let preimage = vector::empty<u8>();
        append_constant(&mut preimage, FS_GAMMA, true, 5);
        append_constant(&mut preimage, VK_S1_COM_X, true, 32);
        append_constant(&mut preimage, VK_S1_COM_Y, true, 32);
        append_constant(&mut preimage, VK_S2_COM_X, true, 32);
        append_constant(&mut preimage, VK_S2_COM_Y, true, 32);
        append_constant(&mut preimage, VK_S3_COM_X, true, 32);
        append_constant(&mut preimage, VK_S3_COM_Y, true, 32);
        append_constant(&mut preimage, VK_QL_COM_X, true, 32);
        append_constant(&mut preimage, VK_QL_COM_Y, true, 32);
        append_constant(&mut preimage, VK_QR_COM_X, true, 32);
        append_constant(&mut preimage, VK_QR_COM_Y, true, 32);
        append_constant(&mut preimage, VK_QM_COM_X, true, 32);
        append_constant(&mut preimage, VK_QM_COM_Y, true, 32);
        append_constant(&mut preimage, VK_QO_COM_X, true, 32);
        append_constant(&mut preimage, VK_QO_COM_Y, true, 32);
        append_constant(&mut preimage, VK_QK_COM_X, true, 32);
        append_constant(&mut preimage, VK_QK_COM_Y, true, 32);
        append_constant(&mut preimage, VK_QCP_0_X, true, 32);
        append_constant(&mut preimage, VK_QCP_0_Y, true, 32);
        append_constant(&mut preimage, vk, true, 32);
        append_constant(&mut preimage, public_inputs_digest, true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 0), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 1), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 2), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 3), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 4), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 5), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    public fun derive_beta(gamma_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_constant(&mut preimage, FS_BETA, true, 4);
        append_constant(&mut preimage, gamma_not_reduced, true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    public fun derive_alpha(proof: vector<u256>, beta_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_constant(&mut preimage, FS_ALPHA, true, 5);
        append_constant(&mut preimage, beta_not_reduced, true, 32);
        // Bsb22Commitments
        append_constant(&mut preimage, *vector::borrow(&proof, 25), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 26), true, 32);
        // [Z], the commitment to the grand product polynomial
        append_constant(&mut preimage, *vector::borrow(&proof, 17), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 18), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    public fun derive_zeta(proof: vector<u256>, alpha_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_constant(&mut preimage, FS_ZETA, true, 4);
        append_constant(&mut preimage, alpha_not_reduced, true, 32);
        // commitment to the quotient polynomial h
        append_constant(&mut preimage, *vector::borrow(&proof, 6), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 7), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 8), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 9), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 10), true, 32);
        append_constant(&mut preimage, *vector::borrow(&proof, 11), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    #[test]
    public fun test_derive_gamma() {
        let proof = get_proof();
        let gamma = derive_gamma(proof, SphinxInclusionProofVk, SphinxPublicValuesHash);
        assert!(gamma == 0xbec7f35a9a4ab19ed3c1bd4122d8a4ef9e7eaa3a29483c4602cc45d88db86135, 1);
    }

    #[test]
    public fun test_derive_beta() {
        let gamma = 0xbec7f35a9a4ab19ed3c1bd4122d8a4ef9e7eaa3a29483c4602cc45d88db86135;
        let beta = derive_beta(gamma);
        assert!(beta == 0x42fc83c6f494936df5a8d6d66f7b1c92e8f9e3b4f59653a03260e3b61590e031, 1);
    }

    #[test]
    public fun test_derive_alpha() {
        let proof = get_proof();
        let beta = 0x42fc83c6f494936df5a8d6d66f7b1c92e8f9e3b4f59653a03260e3b61590e031;
        let alpha = derive_alpha(proof, beta);
        assert!(alpha == 0x9deb5bee532ca79e9560d86926c70bd8fd8a727cc24a38a0c6c977542cd1db00, 1);
    }

    #[test]
    public fun test_derive_zeta() {
        let proof = get_proof();
        let alpha = 0x9deb5bee532ca79e9560d86926c70bd8fd8a727cc24a38a0c6c977542cd1db00;
        let alpha = derive_zeta(proof, alpha);
        assert!(alpha == 0x16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a, 1);
    }
}
