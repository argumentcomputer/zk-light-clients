module plonk_verifier_addr::plonk_verifier {
    use std::vector;
    use std::hash::{ sha2_256 };
    use plonk_verifier_addr::utilities::{append_value, bytes_to_uint256, powSmall, u256_to_fr, fr_to_u256, u256_to_bytes, new_g1, new_g2, point_acc_mul, prepare_pairing_g1_input, fr_acc_mul, get_coordinates};
    use std::bn254_algebra::{FormatFrMsb, Fr, G1, G2, Gt};
    use std::vector::{length, push_back, trim, reverse, pop_back};
    use aptos_std::crypto_algebra::{add, serialize, deserialize, Element, mul, one, zero, multi_pairing, eq, scalar_mul};

    #[test_only]
    use plonk_verifier_addr::utilities::{get_proof, get_public_inputs};

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
    const ERROR_UNEXPECTED_VK_NB_CUSTOM_GATES_AMOUNT: u64 = 1005;
    const ERROR_PAIRING_KZG_CHECK: u64 = 1006;

    #[test]
    public fun test_verify() {
        let proof = get_proof();
        let public_inputs = get_public_inputs();
        verify(proof, public_inputs);
    }

    public fun verify(proof: vector<u256>, public_inputs: vector<u256>) {
        // technical assert to ensure that VK_NB_CUSTOM_GATES constant has not been changed
        assert!(VK_NB_CUSTOM_GATES == 1, ERROR_UNEXPECTED_VK_NB_CUSTOM_GATES_AMOUNT);

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

        let gamma_non_reduced = derive_gamma(proof, vk, public_inputs_digest);
        let beta_non_reduced = derive_beta(gamma_non_reduced);
        let alpha_non_reduced = derive_alpha(proof, beta_non_reduced);
        let zeta_non_reduced = derive_zeta(proof, alpha_non_reduced);

        assert!(zeta_non_reduced == 0x16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a, 1);

        let gamma = gamma_non_reduced % R_MOD;
        let beta = beta_non_reduced % R_MOD;
        let alpha = alpha_non_reduced % R_MOD;
        let zeta = zeta_non_reduced % R_MOD;

        let zeta_bytes = vector::empty<u8>();
        append_value(&mut zeta_bytes, zeta, true, 32);
        let zeta_fr = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&zeta_bytes));
        let r_mod_minus_one_bytes = vector::empty<u8>();
        append_value(&mut r_mod_minus_one_bytes, R_MOD_MINUS_ONE, true, 32);
        let r_mod_minus_one_fr = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&r_mod_minus_one_bytes));
        let zeta_power_n_minus_one = add(&r_mod_minus_one_fr, &powSmall(zeta_fr, VK_DOMAIN_SIZE));

        assert!(bytes_to_uint256(serialize<Fr, FormatFrMsb>(&zeta_power_n_minus_one)) == 0x0183624d8a1f2df2d1bc0ea04c97a743b1031835afb4fc9fb25e88f37780deb7, 2);

        let pic = compute_public_inputs_contribution(u256_to_fr(zeta), zeta_power_n_minus_one, public_inputs);
        assert!(bytes_to_uint256(serialize<Fr, FormatFrMsb>(&pic)) == 0x196d1aee13f8d282bf445d393e9ef0f5d6d2eccdb97fbc2696f7b73878552b01, 3);

        let pic_custom_gates = compute_public_inputs_contribution_from_custom_gates(proof, u256_to_fr(zeta), zeta_power_n_minus_one, (length(&public_inputs) as u256));
        assert!(bytes_to_uint256(serialize<Fr, FormatFrMsb>(&pic_custom_gates)) == 0x0de62ecfdd3191e71fb9a52bfbefd0ff1182e916b8d9264e96e2279a1171fd03, 4);

        let l_pi = add(&pic, &pic_custom_gates);
        assert!(bytes_to_uint256(serialize<Fr, FormatFrMsb>(&l_pi)) == 0x275349bdf12a6469defe02653a8ec1f4e855d5e47258e2752dd9ded289c72804, 5);

        let alpha_square_lagrange_0 = compute_alpha_square_lagrange_0(zeta, zeta_power_n_minus_one, alpha);
        assert!(bytes_to_uint256(serialize<Fr, FormatFrMsb>(&alpha_square_lagrange_0)) == 0x1e5753617012c75058de839245263e8b961d4742abf030d3d44ada59d6211299, 6);

        let opening_linearized_polynomial_zeta = verify_opening_linearized_polynomial(proof, beta, gamma, alpha, alpha_square_lagrange_0, l_pi);
        assert!(opening_linearized_polynomial_zeta == 0x148dee9d4e089cd0abea3cc2fd889ceb0f54a8456de664ed8ad905a13ea764e9, 7);

        // TODO folding stuff
        let state_folded_digest_x: u256 = 0x101b42e285f51c7865c0de9e80baf88f27968bfd0996898217514839998e4055;
        let state_folded_digest_y: u256 = 0x1e5fc59354f785f77dd3baad2cd6f2e29826046cab1885def6732254a2e454be;
        let state_folded_claimed_evals: u256 = 0x1e599360ddb54b11753655d2bd2189b3d498c256e8b45d2c1595bc1e1a7dc610;

        // TODO adding computation of linearized polynomial

        let linearized_polynomial_x = 0x13e5b420a81184cc432f863784d667a183a6a0352aba9c04a28ea4d27a2fe235;
        let linearized_polynomial_y = 0x1d247f83ce0b12465c66efd5c68cf00fdba90b274f3dc94515787b9b5c013b8a;

        let gamma_kzg = compute_gamma_kzg(proof, zeta, linearized_polynomial_x, linearized_polynomial_y, opening_linearized_polynomial_zeta);
        assert!(gamma_kzg == 0x27d3410c7afdd4967e71d28cb34b5595eca2614e3c0a7601891c3554b7568241, 8);

        let (folded_digests, folded_qoutients) = batch_verify_multi_points(proof, zeta, gamma_kzg, state_folded_digest_x, state_folded_digest_y, state_folded_claimed_evals);
        let (fd_x, fd_y) = get_coordinates(folded_digests);
        let (fq_x, fq_y) = get_coordinates(folded_qoutients);

        check_pairing_kzg(fd_x, fd_y, fq_x, fq_y);
    }

    public fun derive_gamma(proof: vector<u256>, vk: u256, public_inputs_digest: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_GAMMA, true, 5);
        append_value(&mut preimage, VK_S1_COM_X, true, 32);
        append_value(&mut preimage, VK_S1_COM_Y, true, 32);
        append_value(&mut preimage, VK_S2_COM_X, true, 32);
        append_value(&mut preimage, VK_S2_COM_Y, true, 32);
        append_value(&mut preimage, VK_S3_COM_X, true, 32);
        append_value(&mut preimage, VK_S3_COM_Y, true, 32);
        append_value(&mut preimage, VK_QL_COM_X, true, 32);
        append_value(&mut preimage, VK_QL_COM_Y, true, 32);
        append_value(&mut preimage, VK_QR_COM_X, true, 32);
        append_value(&mut preimage, VK_QR_COM_Y, true, 32);
        append_value(&mut preimage, VK_QM_COM_X, true, 32);
        append_value(&mut preimage, VK_QM_COM_Y, true, 32);
        append_value(&mut preimage, VK_QO_COM_X, true, 32);
        append_value(&mut preimage, VK_QO_COM_Y, true, 32);
        append_value(&mut preimage, VK_QK_COM_X, true, 32);
        append_value(&mut preimage, VK_QK_COM_Y, true, 32);
        append_value(&mut preimage, VK_QCP_0_X, true, 32);
        append_value(&mut preimage, VK_QCP_0_Y, true, 32);
        append_value(&mut preimage, vk, true, 32);
        append_value(&mut preimage, public_inputs_digest, true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 0), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 1), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 2), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 3), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 4), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 5), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    public fun derive_beta(gamma_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_BETA, true, 4);
        append_value(&mut preimage, gamma_not_reduced, true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    public fun derive_alpha(proof: vector<u256>, beta_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_ALPHA, true, 5);
        append_value(&mut preimage, beta_not_reduced, true, 32);
        // Bsb22Commitments
        append_value(&mut preimage, *vector::borrow(&proof, 25), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 26), true, 32);
        // [Z], the commitment to the grand product polynomial
        append_value(&mut preimage, *vector::borrow(&proof, 17), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 18), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    public fun derive_zeta(proof: vector<u256>, alpha_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_ZETA, true, 4);
        append_value(&mut preimage, alpha_not_reduced, true, 32);
        // commitment to the quotient polynomial h
        append_value(&mut preimage, *vector::borrow(&proof, 6), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 7), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 8), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 9), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 10), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 11), true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    // TODO: simplify this function by splitting onto isolated sub-funcitons
    public fun compute_public_inputs_contribution(zeta: Element<Fr>, zeta_power_n_minus_one: Element<Fr>, public_inputs: vector<u256>): Element<Fr> {
        // sum_pi_wo_api_commit function from Solidity contract
        let ins = public_inputs;
        let n = length(&ins);

        // batch_compute_lagranges_at_z
        let zn = mul(&zeta_power_n_minus_one, &u256_to_fr(VK_INV_DOMAIN_SIZE));
        let _mPtr = vector::empty<Element<Fr>>();
        let i = 0;
        let w = one<Fr>();
        let tmp: u256;
        let tmp_fr: Element<Fr>;
        while (i < n) {
            tmp = R_MOD - fr_to_u256(w);
            tmp_fr = add(&zeta, &u256_to_fr(tmp));
            push_back(&mut _mPtr, tmp_fr);

            w = mul(&w, &u256_to_fr(VK_OMEGA));

            i = i + 1
        };
        let ins_inner = copy _mPtr;

        let new_len = length(&_mPtr) - 1;
        trim(&mut _mPtr, new_len);

        // batch_invert
        push_back(&mut _mPtr, one<Fr>());

        let mPtr_input = copy _mPtr;

        reverse(&mut _mPtr);

        let mPtr = vector::empty<Element<Fr>>();
        let i = 0;
        let tmp;
        while (i < n) {
            let prev = vector::borrow(&_mPtr, i);
            let cur = vector::borrow(&ins_inner, i);
            tmp = mul(prev, cur);
            push_back(&mut mPtr, tmp);

            i = i + 1;
        };

        let inv = powSmall(pop_back(&mut mPtr), R_MOD - 2);

        reverse(&mut ins_inner);

        let ins_ = vector::empty<Element<Fr>>();
        let i = 0;
        let cur;
        while (i < n) {
            cur = mul(&inv, vector::borrow(&mPtr_input, i));
            push_back(&mut ins_, cur);

            inv = mul(&inv, vector::borrow(&ins_inner, i));
            i = i + 1;
        };

        reverse(&mut ins_);

        let li = vector::empty<Element<Fr>>();
        let i = 0;
        let tmp_fr;
        let w = one<Fr>();
        while (i < n) {
            tmp_fr = mul(&w, &mul(vector::borrow(&ins_, i), &zn));
            push_back(&mut li, tmp_fr);
            w = mul(&w, &u256_to_fr(VK_OMEGA));

            i = i + 1
        };

        let i = 0;
        let tmp;
        let pi_wo_commit = zero<Fr>();
        let left;
        let right;
        while (i < n) {
            left = *vector::borrow(&li, i);
            right = u256_to_fr(*vector::borrow(&ins, i));
            tmp = mul(&left, &right);
            pi_wo_commit = add(&pi_wo_commit, &tmp);

            i = i + 1
        };
        pi_wo_commit
    }

    public fun compute_public_inputs_contribution_from_custom_gates(proof: vector<u256>, zeta: Element<Fr>, zeta_power_n_minus_one: Element<Fr>, nb_public_inputs: u256): Element<Fr> {
        let i = nb_public_inputs + VK_INDEX_COMMIT_API_0;

        let w = powSmall(u256_to_fr(VK_OMEGA), i);
        let i = add(&zeta, &u256_to_fr(R_MOD - fr_to_u256(w)));
        let w = mul(&w, &u256_to_fr(VK_INV_DOMAIN_SIZE));
        let i = powSmall(i, R_MOD - 2);
        let w = mul(&w, &i);
        let ith_lagrange = mul(&w, &zeta_power_n_minus_one);

        let calldataload_p: u256 = *vector::borrow(&proof, 25);
        let calldataload_p_32: u256 = *vector::borrow(&proof, 26);

        let preimage = vector::empty<u8>();
        append_value(&mut preimage, HASH_FR_ZERO_UINT256, true, 32);
        append_value(&mut preimage, HASH_FR_ZERO_UINT256, true, 32);
        append_value(&mut preimage, calldataload_p, true, 32);
        append_value(&mut preimage, calldataload_p_32, true, 32);
        append_value(&mut preimage, 0, true, 1);
        append_value(&mut preimage, (HASH_FR_LEN_IN_BYTES as u256), true, 1);
        append_value(&mut preimage, 0, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x53, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x2d, true, 1);
        append_value(&mut preimage, 0x50, true, 1);
        append_value(&mut preimage, 0x6c, true, 1);
        append_value(&mut preimage, 0x6f, true, 1);
        append_value(&mut preimage, 0x6e, true, 1);
        append_value(&mut preimage, 0x6b, true, 1);
        append_value(&mut preimage, (HASH_FR_SIZE_DOMAIN as u256), true, 1);
        let b0 = sha2_256(preimage);

        preimage = vector::empty<u8>();
        append_value(&mut preimage, bytes_to_uint256(b0), true, 32);
        append_value(&mut preimage, (HASH_FR_ONE as u256), true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x53, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x2d, true, 1);
        append_value(&mut preimage, 0x50, true, 1);
        append_value(&mut preimage, 0x6c, true, 1);
        append_value(&mut preimage, 0x6f, true, 1);
        append_value(&mut preimage, 0x6e, true, 1);
        append_value(&mut preimage, 0x6b, true, 1);
        append_value(&mut preimage, (HASH_FR_SIZE_DOMAIN as u256), true, 1);
        let b1 = sha2_256(preimage);

        let preimage = vector::empty<u8>();
        append_value(&mut preimage, bytes_to_uint256(b0) ^ bytes_to_uint256(b1), true, 32);
        append_value(&mut preimage, (HASH_FR_TWO as u256), true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x53, true, 1);
        append_value(&mut preimage, 0x42, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x32, true, 1);
        append_value(&mut preimage, 0x2d, true, 1);
        append_value(&mut preimage, 0x50, true, 1);
        append_value(&mut preimage, 0x6c, true, 1);
        append_value(&mut preimage, 0x6f, true, 1);
        append_value(&mut preimage, 0x6e, true, 1);
        append_value(&mut preimage, 0x6b, true, 1);
        append_value(&mut preimage, (HASH_FR_SIZE_DOMAIN as u256), true, 1);
        let hash = sha2_256(preimage);

        let b1_fr = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&u256_to_bytes(bytes_to_uint256(b1) % R_MOD)));
        let res = mul(&b1_fr, &u256_to_fr(HASH_FR_BB));
        let hash_shifted = bytes_to_uint256(hash) >> 128;
        let hash_fr = add(&res, &u256_to_fr(hash_shifted));
        let pi_commit = mul(&hash_fr, &ith_lagrange);
        pi_commit
    }

    public fun compute_alpha_square_lagrange_0(zeta: u256, zeta_power_n_minus_one: Element<Fr>, alpha: u256): Element<Fr> {
        let den = add(&u256_to_fr(zeta), &u256_to_fr(R_MOD_MINUS_ONE));
        let den = powSmall(den, R_MOD - 2);
        let den = mul(&den, &u256_to_fr(VK_INV_DOMAIN_SIZE));
        let res = mul(&den, &zeta_power_n_minus_one);
        let res = mul(&res, &u256_to_fr(alpha));
        let alpha_square_lagrange_0 = mul(&res, &u256_to_fr(alpha));
        alpha_square_lagrange_0
    }

    public fun verify_opening_linearized_polynomial(proof: vector<u256>, beta: u256, gamma: u256, alpha: u256, alpha_square_lagrange_0: Element<Fr>, pic: Element<Fr>): u256 {
        let s1 = mul(&u256_to_fr(*vector::borrow(&proof, 15)), &u256_to_fr(beta));
        let s1 = add(&s1, &u256_to_fr(gamma));
        let s1 = add(&s1, &u256_to_fr(*vector::borrow(&proof, 12)));

        let s2 = mul(&u256_to_fr(*vector::borrow(&proof, 16)), &u256_to_fr(beta));
        let s2 = add(&s2, &u256_to_fr(gamma));
        let s2 = add(&s2, &u256_to_fr(*vector::borrow(&proof, 13)));

        let o = add(&u256_to_fr(*vector::borrow(&proof, 14)), &u256_to_fr(gamma));

        let s1 = mul(&s1, &s2);
        let s1 = mul(&s1, &o);
        let s1 = mul(&s1, &u256_to_fr(alpha));
        let s1 = mul(&s1, &u256_to_fr(*vector::borrow(&proof, 19)));

        let s1 = add(&s1, &pic);
        let s2 = (R_MOD - fr_to_u256(alpha_square_lagrange_0)) % R_MOD;
        let s1 = add(&s1, &u256_to_fr(s2));
        let s1 = (R_MOD - fr_to_u256(s1)) % R_MOD;

        s1
    }

    public fun compute_gamma_kzg(proof: vector<u256>, zeta: u256, linearized_polynomial_x: u256, linearized_polynomial_y: u256, opening_linearized_polynomial_zeta: u256): u256  {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_GAMMA_KZG, true, 5);
        append_value(&mut preimage, zeta, true, 32);
        append_value(&mut preimage, linearized_polynomial_x, true, 32);
        append_value(&mut preimage, linearized_polynomial_y, true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 0), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 1), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 2), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 3), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 4), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 5), true, 32);
        append_value(&mut preimage, VK_S1_COM_X, true, 32);
        append_value(&mut preimage, VK_S1_COM_Y, true, 32);
        append_value(&mut preimage, VK_S2_COM_X, true, 32);
        append_value(&mut preimage, VK_S2_COM_Y, true, 32);
        append_value(&mut preimage, VK_QCP_0_X, true, 32);
        append_value(&mut preimage, VK_QCP_0_Y, true, 32);
        append_value(&mut preimage, opening_linearized_polynomial_zeta, true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 12), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 13), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 14), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 15), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 16), true, 32);
        // Breaking change happens if VK_NB_CUSTOM_GATES != 1.
        // In original Solidity contract the number of proof chunks appended is computed as VK_NB_CUSTOM_GATES * 32)
        append_value(&mut preimage, *vector::borrow(&proof, 24), true, 32);
        append_value(&mut preimage, *vector::borrow(&proof, 19), true, 32);

        let hash = sha2_256(preimage);
        let hash_reduced = bytes_to_uint256(hash) % R_MOD;
        hash_reduced
    }

    public fun check_pairing_kzg(folded_digests_x: u256, folded_digests_y: u256, folded_quotients_x: u256, folded_quotients_y: u256) {
        // G1
        let pairing_input_0: u256 = folded_digests_x;
        let pairing_input_1: u256 = folded_digests_y;
        // G2
        let pairing_input_2: u256 = G2_SRS_0_X_0;
        let pairing_input_3: u256 = G2_SRS_0_X_1;
        let pairing_input_4: u256 = G2_SRS_0_Y_0;
        let pairing_input_5: u256 = G2_SRS_0_Y_1;
        // G1
        let pairing_input_6: u256 = folded_quotients_x;
        let pairing_input_7: u256 = folded_quotients_y;
        // G2
        let pairing_input_8: u256 = G2_SRS_1_X_0;
        let pairing_input_9: u256 = G2_SRS_1_X_1;
        let pairing_input_10: u256 = G2_SRS_1_Y_0;
        let pairing_input_11: u256 = G2_SRS_1_Y_1;

        let g1_elements = vector::empty<Element<G1>>();
        push_back(&mut g1_elements, new_g1(pairing_input_0, pairing_input_1));
        push_back(&mut g1_elements, new_g1(pairing_input_6, pairing_input_7));

        let g2_elements = vector::empty<Element<G2>>();
        push_back(&mut g2_elements, new_g2(pairing_input_2, pairing_input_3, pairing_input_4, pairing_input_5));
        push_back(&mut g2_elements, new_g2(pairing_input_8, pairing_input_9, pairing_input_10, pairing_input_11));
        let gt_element = multi_pairing<G1, G2, Gt>(&g1_elements, &g2_elements);
        assert!(eq(&gt_element, &zero<Gt>()), ERROR_PAIRING_KZG_CHECK);
    }

    // TODO: validate verificaion on various proofs since there are places where arithmetic overflow may happen
    public fun batch_verify_multi_points(proof: vector<u256>, zeta: u256, gamma_kzg: u256, state_folded_digest_x: u256, state_folded_digest_y: u256, state_folded_claimed_evals: u256): (Element<G1>, Element<G1>) {
        let proof_batch_opening_at_zeta_x: u256 = *vector::borrow(&proof, 20);
        let proof_batch_opening_at_zeta_y: u256 = *vector::borrow(&proof, 21);
        let proof_grand_product_commitment_x: u256 = *vector::borrow(&proof, 17);
        let proof_grand_product_commitment_y: u256 = *vector::borrow(&proof, 18);
        let proof_opening_at_zeta_omega_x: u256 = *vector::borrow(&proof, 22);
        let proof_opening_at_zeta_omega_y: u256 = *vector::borrow(&proof, 23);
        let proof_grand_product_at_zeta_omega: u256 = *vector::borrow(&proof, 19);

        let preimage = vector::empty<u8>();
        append_value(&mut preimage, state_folded_digest_x, true, 32);
        append_value(&mut preimage, state_folded_digest_y, true, 32);
        append_value(&mut preimage, proof_batch_opening_at_zeta_x, true, 32);
        append_value(&mut preimage, proof_batch_opening_at_zeta_y, true, 32);
        append_value(&mut preimage, proof_grand_product_commitment_x, true, 32);
        append_value(&mut preimage, proof_grand_product_commitment_y, true, 32);
        append_value(&mut preimage, proof_opening_at_zeta_omega_x, true, 32);
        append_value(&mut preimage, proof_opening_at_zeta_omega_y, true, 32);
        append_value(&mut preimage, zeta, true, 32);
        append_value(&mut preimage, gamma_kzg, true, 32);

        let hash = sha2_256(preimage);
        let random = bytes_to_uint256(hash) % R_MOD;

        let proof_opening_at_zeta_omega = new_g1(proof_opening_at_zeta_omega_x, proof_opening_at_zeta_omega_y);
        let proof_batch_opening_at_zeta = new_g1(proof_batch_opening_at_zeta_x, proof_batch_opening_at_zeta_y);
        let folded_quotients = point_acc_mul(proof_opening_at_zeta_omega, u256_to_fr(random), proof_batch_opening_at_zeta);
        let folded_quotients = prepare_pairing_g1_input(folded_quotients, P_MOD);

        let proof_grand_product_commitment = new_g1(proof_grand_product_commitment_x, proof_grand_product_commitment_y);
        let state_folded_digests = new_g1(state_folded_digest_x, state_folded_digest_y);
        let folded_digests = point_acc_mul(proof_grand_product_commitment, u256_to_fr(random), state_folded_digests);

        let folded_evals = fr_acc_mul(state_folded_claimed_evals, proof_grand_product_at_zeta_omega, random);

        let g1_srs = new_g1(G1_SRS_X, G1_SRS_Y);
        let folded_evals_commit = scalar_mul(&g1_srs, &folded_evals);

        let folded_evals_commit = prepare_pairing_g1_input(folded_evals_commit, P_MOD);

        let folded_digests = add(&folded_digests, &folded_evals_commit);

        let folded_points_quotients = scalar_mul(&new_g1(proof_batch_opening_at_zeta_x, proof_batch_opening_at_zeta_y), &u256_to_fr(zeta));

        let zeta_omega = mul(&u256_to_fr(zeta), &u256_to_fr(VK_OMEGA));
        let random = mul(&u256_to_fr(random), &zeta_omega);

        let folded_points_quotients = point_acc_mul(proof_opening_at_zeta_omega, random, folded_points_quotients);

        let folded_digests = add(&folded_digests, &folded_points_quotients);

        (folded_digests, folded_quotients)
    }

    #[test]
    public fun test_pairing_kzg_check() {
        let folded_digests_x: u256 = 0x08b99791fe52556d6763cc2ef120620e81e6403dc1aea7b14be1d96f1f53cb57;
        let folded_digests_y: u256 = 0x0bb5831359b594a93730d4fcd7ce5bf1e89c589f0c230465e5dc993694c5cda3;

        let folded_quotients_x: u256 = 0x1372be68afe235fcad22b0f5bbee8120b4144cf12e8be05e0fee58b2edaefb99;
        let folded_quotients_y: u256 = 0x009eed110f00d9b208e8a9b6fd71e471e6180c17fb58a9b09693da3c0b7a8872;

        check_pairing_kzg(folded_digests_x, folded_digests_y, folded_quotients_x, folded_quotients_y);
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
        let zeta = derive_zeta(proof, alpha);
        assert!(zeta == 0x16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a, 1);
    }

    #[test]
    public fun test_compute_zeta_power_r_minus_one() {
        let zeta = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a"));
        let r_mod_minus_one_element = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"));
        let zeta_power_n_minus_one = add(&r_mod_minus_one_element, &powSmall(zeta, VK_DOMAIN_SIZE));
        assert!(&serialize<Fr, FormatFrMsb>(&zeta_power_n_minus_one) == &x"0183624d8a1f2df2d1bc0ea04c97a743b1031835afb4fc9fb25e88f37780deb7", 1);
    }
}

