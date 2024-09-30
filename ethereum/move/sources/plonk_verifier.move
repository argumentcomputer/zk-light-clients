module plonk_verifier_addr::plonk_verifier {
    use std::vector;
    use std::hash::{ sha2_256 };
    use plonk_verifier_addr::utilities::{append_value, bytes_to_uint256, powSmall, u256_to_fr, fr_to_u256, u256_to_bytes, new_g1, new_g2, point_acc_mul, prepare_pairing_g1_input, fr_acc_mul, get_coordinates, unset_first_bit};
    use std::bn254_algebra::{FormatFrMsb, Fr, G1, G2, Gt};
    use std::vector::{length, push_back, trim, reverse, pop_back};
    use aptos_std::crypto_algebra::{add, deserialize, Element, mul, one, zero, multi_pairing, eq, scalar_mul};
    #[test_only]
    use aptos_std::crypto_algebra::serialize;

    // BN254 curve constants
    const R_MOD: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    const R_MOD_MINUS_ONE: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    const P_MOD: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Aztec SRS constants
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

    // Plonk verifier key constants
    const VK_NB_PUBLIC_INPUTS: u64 = 2;
    const VK_DOMAIN_SIZE: u256 = 67108864;
    const VK_INV_DOMAIN_SIZE: u256 = 0x30644e66c81e03716be83b486d6feabcc7ddd0fe6cbf5e72d585d142f7829b05;
    const VK_OMEGA: u256 = 0x1067569af1ff73b20113eff9b8d89d4a605b52b63d68f9ae1c79bd572f4e9212;
    const VK_QL_COM_X: u256 = 0x001bb15754e011a2a423c73e153aa852b09aef41cc2b1295694ccc6f9cf300d5;
    const VK_QL_COM_Y: u256 = 0x0483c90c0cfc2de75643c07e4fede2aa9c2f5eb6bd094a1c28590f2a23bc29e5;
    const VK_QR_COM_X: u256 = 0x147ab4297dbf87265d3ab42c6300ec8b0f59e7258e8ff9243a81b956e2b402ad;
    const VK_QR_COM_Y: u256 = 0x26f95651cfe1c49de5d5765b6cfad6b8a34348a54713d5fc55f1b92ab107265d;
    const VK_QM_COM_X: u256 = 0x0be8a641a5e52b4b2026fd30e9ea51dbb57418891fc3372e49ff13e514622705;
    const VK_QM_COM_Y: u256 = 0x16aa04840c5dba028688923bb4abe223662512feb496e3074f239ca6c0864978;
    const VK_QO_COM_X: u256 = 0x278e984160a07cd1d9896aef99a0d92dfd8e0f4f3d08ca91b51cc1467b1c8ab7;
    const VK_QO_COM_Y: u256 = 0x1beb5f8491dae2d9ea489874553b0f3d7581dd6cdc30df0fd5d52d55141b6eec;
    const VK_QK_COM_X: u256 = 0x0452136eca9a6e04c6a331a47f505f8ec363d31a060d96fbe22b290ecd64f813;
    const VK_QK_COM_Y: u256 = 0x2736812e149a16907a34f9903a3591d1a018e19101c01dfb675e9dfb06f813c7;
    const VK_S1_COM_X: u256 = 0x06cbc24cbd62ee09a95672a3c251abc39baed40c7a8682a556291b5efb7a5b10;
    const VK_S1_COM_Y: u256 = 0x0be779e26f0936ebcf1368e98ae78bed27e08f796b7865d47cee108abad8ee09;
    const VK_S2_COM_X: u256 = 0x2b06a434bea3630550a316e1047568944b33c8ba0f79e424969603116b2770ac;
    const VK_S2_COM_Y: u256 = 0x065a2d1e37b4d5564937baf39cadb76f22348e027bc3d2f3db4fd559c46ffe87;
    const VK_S3_COM_X: u256 = 0x04a2cea642f8ee9d9b73e8715a74e84e30c2625d4eb3175e242c5b7e37da890d;
    const VK_S3_COM_Y: u256 = 0x04c71e553bcf61e4d5f85b2ffc1b1dab4a4a7f4d76a0b2de19300e42ff15694a;
    const VK_COSET_SHIFT: u256 = 5;

    const VK_QCP_0_X: u256 = 0x109e800acb84a21685e8eabdb98a8c4ab1abc939341902b34dcb3f1a3aa6d325;
    const VK_QCP_0_Y: u256 = 0x195cffe8af99edb66d60be290baa002cdec78a7b9998259f88f818f32fa3e225;
    const VK_INDEX_COMMIT_API_0: u256 = 31314682;

    const VK_NB_CUSTOM_GATES: u64 = 1;

    // Utils for Fiat Shamir
    const FS_ALPHA: u256 = 0x616C706861;
    const FS_BETA: u256 = 0x62657461;
    const FS_GAMMA: u256 = 0x67616d6d61;
    const FS_ZETA: u256 = 0x7a657461;
    const FS_GAMMA_KZG: u256 = 0x67616d6d61;

    // Utils for hash_fr
    const HASH_FR_BB: u256 = 0x0000000000000000000000000000000100000000000000000000000000000000; // 2**128
    const HASH_FR_ZERO_UINT256: u256 = 0;
    const HASH_FR_LEN_IN_BYTES: u8 = 48;
    const HASH_FR_SIZE_DOMAIN: u8 = 11;
    const HASH_FR_ONE: u8 = 1;
    const HASH_FR_TWO: u8 = 2;

    // Move verifier errors
    const ERROR_NB_PUBLIC_INPUTS: u64 = 1001;
    const ERROR_INPUTS_SIZE: u64 = 1002;
    const ERROR_PROOF_SIZE: u64 = 1003;
    const ERROR_PROOF_OPENING_SIZE: u64 = 1004;
    const ERROR_UNEXPECTED_VK_NB_CUSTOM_GATES_AMOUNT: u64 = 1005;
    const ERROR_PAIRING_KZG_CHECK: u64 = 1006;

    public fun verify(proof: vector<u256>, vk: u256, raw_public_inputs: vector<u8>) {
        let public_inputs = vector::empty<u256>();
        push_back(&mut public_inputs, vk);
        push_back(&mut public_inputs, bytes_to_uint256(sha2_256(raw_public_inputs)) & ((1 << 253) - 1));
        verify_inner(proof, public_inputs);
    }

    fun verify_inner(proof: vector<u256>, public_inputs: vector<u256>) {
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

        let pic = compute_public_inputs_contribution(u256_to_fr(zeta), zeta_power_n_minus_one, public_inputs);

        let pic_custom_gates = compute_public_inputs_contribution_from_custom_gates(proof, u256_to_fr(zeta), zeta_power_n_minus_one, (length(&public_inputs) as u256));

        let l_pi = add(&pic, &pic_custom_gates);

        let alpha_square_lagrange_0 = compute_alpha_square_lagrange_0(zeta, zeta_power_n_minus_one, alpha);

        let opening_linearized_polynomial_zeta = verify_opening_linearized_polynomial(proof, beta, gamma, alpha, alpha_square_lagrange_0, l_pi);

        let folded_h = fold_h(proof, zeta, fr_to_u256(zeta_power_n_minus_one));

        let (linearized_polynomial_x, linearized_polynomial_y) = compute_commitment_linearized_polynomial(proof, beta, gamma, alpha, zeta, alpha_square_lagrange_0, folded_h);

        let gamma_kzg = compute_gamma_kzg(proof, zeta, linearized_polynomial_x, linearized_polynomial_y, opening_linearized_polynomial_zeta);

        let (state_folded_digest_x, state_folded_digest_y, state_folded_claimed_evals) = fold_state(proof, gamma_kzg, linearized_polynomial_x, linearized_polynomial_y, opening_linearized_polynomial_zeta);

        let (folded_digests, folded_qoutients) = batch_verify_multi_points(proof, zeta, gamma_kzg, state_folded_digest_x, state_folded_digest_y, state_folded_claimed_evals);
        let (fd_x, fd_y) = get_coordinates(folded_digests);
        let (fq_x, fq_y) = get_coordinates(folded_qoutients);

        check_pairing_kzg(fd_x, fd_y, fq_x, fq_y);
    }

    fun derive_gamma(proof: vector<u256>, vk: u256, public_inputs_digest: u256): u256 {
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

    fun derive_beta(gamma_not_reduced: u256): u256 {
        let preimage = vector::empty<u8>();
        append_value(&mut preimage, FS_BETA, true, 4);
        append_value(&mut preimage, gamma_not_reduced, true, 32);
        bytes_to_uint256(sha2_256(preimage))
    }

    fun derive_alpha(proof: vector<u256>, beta_not_reduced: u256): u256 {
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

    fun derive_zeta(proof: vector<u256>, alpha_not_reduced: u256): u256 {
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
    fun compute_public_inputs_contribution(zeta: Element<Fr>, zeta_power_n_minus_one: Element<Fr>, public_inputs: vector<u256>): Element<Fr> {
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

    fun compute_public_inputs_contribution_from_custom_gates(proof: vector<u256>, zeta: Element<Fr>, zeta_power_n_minus_one: Element<Fr>, nb_public_inputs: u256): Element<Fr> {
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

    fun compute_alpha_square_lagrange_0(zeta: u256, zeta_power_n_minus_one: Element<Fr>, alpha: u256): Element<Fr> {
        let den = add(&u256_to_fr(zeta), &u256_to_fr(R_MOD_MINUS_ONE));
        let den = powSmall(den, R_MOD - 2);
        let den = mul(&den, &u256_to_fr(VK_INV_DOMAIN_SIZE));
        let res = mul(&den, &zeta_power_n_minus_one);
        let res = mul(&res, &u256_to_fr(alpha));
        let alpha_square_lagrange_0 = mul(&res, &u256_to_fr(alpha));
        alpha_square_lagrange_0
    }

    fun verify_opening_linearized_polynomial(proof: vector<u256>, beta: u256, gamma: u256, alpha: u256, alpha_square_lagrange_0: Element<Fr>, pic: Element<Fr>): u256 {
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

    fun compute_gamma_kzg(proof: vector<u256>, zeta: u256, linearized_polynomial_x: u256, linearized_polynomial_y: u256, opening_linearized_polynomial_zeta: u256): u256  {
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

    fun check_pairing_kzg(folded_digests_x: u256, folded_digests_y: u256, folded_quotients_x: u256, folded_quotients_y: u256) {
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
    fun batch_verify_multi_points(proof: vector<u256>, zeta: u256, gamma_kzg: u256, state_folded_digest_x: u256, state_folded_digest_y: u256, state_folded_claimed_evals: u256): (Element<G1>, Element<G1>) {
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

    fun fold_h(proof: vector<u256>, zeta: u256, zeta_power_n_minus_one: u256): Element<G1> {
        let n_plus_two = VK_DOMAIN_SIZE + 2;
        let proof_h_2_x: u256 = *vector::borrow(&proof, 10);
        let proof_h_2_y: u256 = *vector::borrow(&proof, 11);
        let proof_h_1_x: u256 = *vector::borrow(&proof, 8);
        let proof_h_1_y: u256 = *vector::borrow(&proof, 9);
        let proof_h_0_x: u256 = *vector::borrow(&proof, 6);
        let proof_h_0_y: u256 = *vector::borrow(&proof, 7);

        let zeta_power_n_plus_two = powSmall(u256_to_fr(zeta), n_plus_two);
        let folded_h = scalar_mul(&new_g1(proof_h_2_x, proof_h_2_y), &zeta_power_n_plus_two);
        let folded_h = add(&folded_h, &new_g1(proof_h_1_x, proof_h_1_y));
        let folded_h = scalar_mul(&folded_h, &zeta_power_n_plus_two);
        let folded_h = add(&folded_h, &new_g1(proof_h_0_x, proof_h_0_y));
        let folded_h = scalar_mul(&folded_h, &u256_to_fr(zeta_power_n_minus_one));
        let folded_h = prepare_pairing_g1_input(folded_h, P_MOD);
        folded_h
    }

    fun fold_state(proof: vector<u256>, gamma_kzg: u256, linearized_polynomial_x: u256, linearized_polynomial_y: u256, opening_linearized_polynomial_zeta: u256): (u256, u256, u256) {
        let proof_l_com_x: u256 = *vector::borrow(&proof, 0);
        let proof_l_com_y: u256 = *vector::borrow(&proof, 1);
        let proof_l_at_zeta: u256 = *vector::borrow(&proof, 12);
        let proof_r_at_zeta: u256 = *vector::borrow(&proof, 13);
        let proof_o_at_zeta: u256 = *vector::borrow(&proof, 14);
        let proof_s1_at_zeta: u256 = *vector::borrow(&proof, 15);
        let proof_s2_at_zeta: u256 = *vector::borrow(&proof, 16);
        let proof_opening_qcp_at_zeta: u256 = *vector::borrow(&proof, 24);

        let proof_r_com_x: u256 = *vector::borrow(&proof, 2);
        let proof_r_com_y: u256 = *vector::borrow(&proof, 3);
        let proof_o_com_x: u256 = *vector::borrow(&proof, 4);
        let proof_o_com_y: u256 = *vector::borrow(&proof, 5);

        let state_folded_digest = point_acc_mul(new_g1(proof_l_com_x, proof_l_com_y), u256_to_fr(gamma_kzg), new_g1(linearized_polynomial_x, linearized_polynomial_y));

        let state_folded_claimed_values = fr_acc_mul(opening_linearized_polynomial_zeta, proof_l_at_zeta, gamma_kzg);

        let acc_gamma = mul(&u256_to_fr(gamma_kzg), &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(proof_r_com_x, proof_r_com_y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_r_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(proof_o_com_x, proof_o_com_y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_o_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(VK_S1_COM_X, VK_S1_COM_Y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_s1_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(VK_S2_COM_X, VK_S2_COM_Y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_s2_at_zeta, fr_to_u256(acc_gamma));

        let acc_gamma = mul(&acc_gamma, &u256_to_fr(gamma_kzg));

        let state_folded_digest = point_acc_mul(new_g1(VK_QCP_0_X, VK_QCP_0_Y), acc_gamma, state_folded_digest);

        let state_folded_claimed_values = fr_acc_mul(fr_to_u256(state_folded_claimed_values), proof_opening_qcp_at_zeta, fr_to_u256(acc_gamma));

        let (a, b) = get_coordinates(state_folded_digest);

        (a, b, fr_to_u256(state_folded_claimed_values))
    }

    fun compute_commitment_linearized_polynomial(
        proof: vector<u256>,
        state_beta: u256,
        state_gamma: u256,
        state_alpha: u256,
        state_zeta: u256,
        alpha_square_lagrange_0: Element<Fr>,
        folded_h: Element<G1>,
    ): (u256, u256) {
        let proof_grand_product_at_zeta_omega: u256 = *vector::borrow(&proof, 19);
        let proof_s1_at_zeta: u256 = *vector::borrow(&proof, 15);
        let proof_l_at_zeta: u256 = *vector::borrow(&proof, 12);
        let proof_s2_at_zeta: u256 = *vector::borrow(&proof, 16);
        let proof_r_at_zeta: u256 = *vector::borrow(&proof, 13);
        let proof_o_at_zeta: u256 = *vector::borrow(&proof, 14);

        let qcp_opening_at_zeta = *vector::borrow(&proof, 24);
        let bsb_commitment_x = *vector::borrow(&proof, 25);
        let bsb_commitment_y = *vector::borrow(&proof, 26);
        let proof_grand_product_commitment_x: u256 = *vector::borrow(&proof, 17);
        let proof_grand_product_commitment_y: u256 = *vector::borrow(&proof, 18);

        let bsb_commitment = vector::empty<Element<G1>>();
        push_back(&mut bsb_commitment, new_g1(bsb_commitment_x, bsb_commitment_y));

        assert!(length(&bsb_commitment) == VK_NB_CUSTOM_GATES, ERROR_UNEXPECTED_VK_NB_CUSTOM_GATES_AMOUNT);

        let u = mul(&u256_to_fr(proof_grand_product_at_zeta_omega), &u256_to_fr(state_beta));
        let v = mul(&u256_to_fr(state_beta), &u256_to_fr(proof_s1_at_zeta));

        let v = add(&v, &u256_to_fr(proof_l_at_zeta));
        let v = add(&v, &u256_to_fr(state_gamma));

        let w = mul(&u256_to_fr(state_beta), &u256_to_fr(proof_s2_at_zeta));
        let w = add(&w, &u256_to_fr(proof_r_at_zeta));
        let w = add(&w, &u256_to_fr(state_gamma));

        let s1 = mul(&u, &v);
        let s1 = mul(&s1, &w);
        let s1 = mul(&s1, &u256_to_fr(state_alpha));

        let coset_square = mul(&u256_to_fr(VK_COSET_SHIFT), &u256_to_fr(VK_COSET_SHIFT));
        let betazeta = mul(&u256_to_fr(state_beta), &u256_to_fr(state_zeta));
        let u = add(&betazeta, &u256_to_fr(proof_l_at_zeta));
        let u = add(&u, &u256_to_fr(state_gamma));

        let v = mul(&betazeta, &u256_to_fr(VK_COSET_SHIFT));
        let v = add(&v, &u256_to_fr(proof_r_at_zeta));
        let v = add(&v, &u256_to_fr(state_gamma));

        let w = mul(&betazeta, &coset_square);
        let w = add(&w, &u256_to_fr(proof_o_at_zeta));
        let w = add(&w, &u256_to_fr(state_gamma));

        let s2 = mul(&u, &v);
        let s2 = mul(&s2, &w);
        let s2 = R_MOD - fr_to_u256(s2);
        let s2 = mul(&u256_to_fr(s2), &u256_to_fr(state_alpha));
        let s2 = add(&s2, &alpha_square_lagrange_0);

        // compute_commitment_linearised_polynomial_ec
        let state_linearized_polynomial = new_g1(VK_QL_COM_X, VK_QL_COM_Y);
        let state_linearized_polynomial = scalar_mul(&state_linearized_polynomial, &u256_to_fr(proof_l_at_zeta));

        let state_linearized_polynomial = point_acc_mul(new_g1(VK_QR_COM_X, VK_QR_COM_Y), u256_to_fr(proof_r_at_zeta), state_linearized_polynomial);

        let rl = mul(&u256_to_fr(proof_l_at_zeta), &u256_to_fr(proof_r_at_zeta));

        let state_linearized_polynomial = point_acc_mul(new_g1(VK_QM_COM_X, VK_QM_COM_Y), rl, state_linearized_polynomial);

        let state_linearized_polynomial = point_acc_mul(new_g1(VK_QO_COM_X, VK_QO_COM_Y), u256_to_fr(proof_o_at_zeta), state_linearized_polynomial);

        let state_linearized_polynomial = add(&new_g1(VK_QK_COM_X, VK_QK_COM_Y), &state_linearized_polynomial);

        let i: u64 = 0;
        while (i < VK_NB_CUSTOM_GATES) {
            state_linearized_polynomial = point_acc_mul(*vector::borrow(&bsb_commitment, i), u256_to_fr(qcp_opening_at_zeta), state_linearized_polynomial);
            i = i + 1
        };
        let state_linearized_polynomial = point_acc_mul(new_g1(VK_S3_COM_X, VK_S3_COM_Y), s1, state_linearized_polynomial);
        let state_linearized_polynomial = point_acc_mul(new_g1(proof_grand_product_commitment_x, proof_grand_product_commitment_y), s2, state_linearized_polynomial);
        let state_linearized_polynomial = add(&state_linearized_polynomial, &folded_h);
        let (x, y) = get_coordinates(state_linearized_polynomial);
        (unset_first_bit(x), unset_first_bit(y))
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
        assert!(gamma == 0x7daa2238a17de361408fb12f3869e06c759aba4e61dd0ff0ea06abe949eb7fd6, 1);
    }

    #[test]
    public fun test_derive_beta() {
        let gamma = 0x7daa2238a17de361408fb12f3869e06c759aba4e61dd0ff0ea06abe949eb7fd6;
        let beta = derive_beta(gamma);
        assert!(beta == 0xa90f698c845f36f6b5bb4d9c64983a89aad40adf5eb6f25b70b39770400506c, 1);
    }

    #[test]
    public fun test_derive_alpha() {
        let proof = get_proof();
        let beta = 0xa90f698c845f36f6b5bb4d9c64983a89aad40adf5eb6f25b70b39770400506c;
        let alpha = derive_alpha(proof, beta);
        assert!(alpha == 0x70cd8944054435d421a4536031e3f0dbb825e409b952b79dbe2d685a87a53a1b, 1);
    }

    #[test]
    public fun test_derive_zeta() {
        let proof = get_proof();
        let alpha = 0x70cd8944054435d421a4536031e3f0dbb825e409b952b79dbe2d685a87a53a1b;
        let zeta = derive_zeta(proof, alpha);
        assert!(zeta == 0x479db46f91629873cd273b3d326956b7bbe0b5bcc64459e2416b18cf890ac66b, 1);
    }

    #[test]
    public fun test_compute_zeta_power_r_minus_one() {
        let zeta = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a"));
        let r_mod_minus_one_element = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"));
        let zeta_power_n_minus_one = add(&r_mod_minus_one_element, &powSmall(zeta, VK_DOMAIN_SIZE));
        assert!(&serialize<Fr, FormatFrMsb>(&zeta_power_n_minus_one) == &x"0183624d8a1f2df2d1bc0ea04c97a743b1031835afb4fc9fb25e88f37780deb7", 1);
    }

    #[test]
    public fun test_verify_inner() {
        let proof = get_proof();
        let public_inputs = get_public_inputs();
        verify_inner(proof, public_inputs);
    }

    #[test]
    public fun test_compute_public_values_hash() {
        let raw_public_inputs = x"e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba010000000000000080";
        let pv_hash = bytes_to_uint256(sha2_256(raw_public_inputs)) & ((1 << 253) - 1);
        assert!(pv_hash == SphinxPublicValuesHash, 1);
    }

    // Actual valid proof instance data generated by Sphinx using inclusion program
    // (from Solidity's inclusion_fixture.json)

    const Proof_chunk_0: u256 = 0x24861767a7e453f220f9a2cec1a9c1ba67cb734c50fe292d8a8cbf475f4ecdd4;
    const Proof_chunk_1: u256 = 0x17e47908ac676f8310850863c5d558f7f4eec2c8ba1388cc944932a3cf5c3714;
    const Proof_chunk_2: u256 = 0x23246685f0aa842f789403288b02dc412a7430eb516b4e8a7e99b1193d32c04b;
    const Proof_chunk_3: u256 = 0x0612df3654f74d051e3e9c24c7be8f34dd570fbf252919dd18243054d5f17255;
    const Proof_chunk_4: u256 = 0x0166587515cf6e2ca1292df05941e075f331b3746e60f89f185317007541fdd6;
    const Proof_chunk_5: u256 = 0x2c6fe406a14b736020653dcca451f63072f0425ca36dfc832021016821836b9d;
    const Proof_chunk_6: u256 = 0x1c15b06039d70b291574e22c8a20bd7fbae0a72d1c57f092a1f03a26489adf7c;
    const Proof_chunk_7: u256 = 0x234247c6fae957f1ab8e1975c6df1c959ed81a6fc53d523b7969312e5ca2e8d4;
    const Proof_chunk_8: u256 = 0x17ba62b8c5f641cec7d6b237ce9fe9f86ce149d31a6329446dce84a21a11cac1;
    const Proof_chunk_9: u256 = 0x2800635f363851471dafc379afaefe984351ffabc891a4db80cda0ad9f5cc69a;
    const Proof_chunk_10: u256 = 0x2b5401747be4b3b86204e611f1213a68d41c55cb1e1770a8ab6c4992abec43d7;
    const Proof_chunk_11: u256 = 0x180e0f1fa44c0a5377f6c0ad11120026e4edfbf7fd00084adedd9d88204578bd;
    const Proof_chunk_12: u256 = 0x17c31c5af075458aa0e56d90190c0fc70c70a55ec4a4159baa6873e2fb610897;
    const Proof_chunk_13: u256 = 0x10d52d1f5c8b4ef6121240eceb465540426ea03db93375958522ad6b0b67137d;
    const Proof_chunk_14: u256 = 0x2e455d147a32298f2f46d6fac9ade31b4dc3484a41bfeb9b5c47f1b90b94b757;
    const Proof_chunk_15: u256 = 0x19f77f014c99f7cc23f099cb3ed4d7d9711e30287ced98c4f94b6d9b036073db;
    const Proof_chunk_16: u256 = 0x1c0ed6b8ed155efc8258b39baa46c9e11e480b22670c6da62388eb7af544fa6c;
    const Proof_chunk_17: u256 = 0x18dfed0be8fda5d1e78fab2f7e75b7e1a0af71cff33303e4fe7a64d358cdc046;
    const Proof_chunk_18: u256 = 0x0a81acc9430df6597682a020b2912aeca5bedf2c3e3104b154bd153f1e1da50a;
    const Proof_chunk_19: u256 = 0x163dabc98c40027c88579514f54236520d4b40ede0214c04cfece063bb999a63;
    const Proof_chunk_20: u256 = 0x0874ec6b6dbf1a62658fb5e021462914f5371bda976a6af43e44c444039a7728;
    const Proof_chunk_21: u256 = 0x17df40bc7d03e0d476be417b10cb978b27f0fb1038ce5b602952eec70d9157f7;
    const Proof_chunk_22: u256 = 0x0ab0d26d6acb3a0b1047585dba494d8279e740efdfe7a042c6108bcc7baca7b9;
    const Proof_chunk_23: u256 = 0x1dfb390967cd9cb41e5302e1adfaf5bff0975a893df88a492c738b2bbea1c600;
    const Proof_chunk_24: u256 = 0x209f9559f36d4ca29487ef7a1a6aeee4bb298e647bc30437f4600764001cfb92;
    const Proof_chunk_25: u256 = 0x031d6f99499cbc8a55a3629abed1d232c35a6f362c23cc2724f74b98fa11300c;
    const Proof_chunk_26: u256 = 0x2fe8a790c98d3cba19dd001c8d0f5cff70ae5fff32da4bc3f60600cde5388adf;

    #[test_only]
    public fun get_proof(): vector<u256> {
        let proof = vector::empty<u256>();
        push_back(&mut proof, Proof_chunk_0);
        push_back(&mut proof, Proof_chunk_1);
        push_back(&mut proof, Proof_chunk_2);
        push_back(&mut proof, Proof_chunk_3);
        push_back(&mut proof, Proof_chunk_4);
        push_back(&mut proof, Proof_chunk_5);
        push_back(&mut proof, Proof_chunk_6);
        push_back(&mut proof, Proof_chunk_7);
        push_back(&mut proof, Proof_chunk_8);
        push_back(&mut proof, Proof_chunk_9);
        push_back(&mut proof, Proof_chunk_10);
        push_back(&mut proof, Proof_chunk_11);
        push_back(&mut proof, Proof_chunk_12);
        push_back(&mut proof, Proof_chunk_13);
        push_back(&mut proof, Proof_chunk_14);
        push_back(&mut proof, Proof_chunk_15);
        push_back(&mut proof, Proof_chunk_16);
        push_back(&mut proof, Proof_chunk_17);
        push_back(&mut proof, Proof_chunk_18);
        push_back(&mut proof, Proof_chunk_19);
        push_back(&mut proof, Proof_chunk_20);
        push_back(&mut proof, Proof_chunk_21);
        push_back(&mut proof, Proof_chunk_22);
        push_back(&mut proof, Proof_chunk_23);
        push_back(&mut proof, Proof_chunk_24);
        push_back(&mut proof, Proof_chunk_25);
        push_back(&mut proof, Proof_chunk_26);
        proof
    }

    const SphinxPublicValuesHash: u256 = 0x0c86aef3959e35623f450cb04bcd7882bbf4774c8bdaabfa155e5c2d9451f0ed;
    const SphinxInclusionProofVk: u256 = 0x00d6b0922b33f4a88cac7a71b76e025fa0dfb9b3a2e74e009bd511db5688bd3d;

    #[test_only]
    public fun get_public_inputs(): vector<u256> {
        let public_inputs = vector::empty<u256>();
        push_back(&mut public_inputs, SphinxInclusionProofVk);
        push_back(&mut public_inputs, SphinxPublicValuesHash);
        public_inputs
    }
}
