module plonk_verifier_addr::utilities {
    use aptos_std::crypto_algebra::{Element, one, mul, deserialize, serialize, scalar_mul, add};
    use std::bn254_algebra::{Fr, FormatFrMsb, G1, FormatG1Uncompr, G2, FormatG2Uncompr};
    use std::vector::{length, push_back, append, trim, reverse, slice};
    use std::vector;

    #[test_only]
    use aptos_std::crypto_algebra::{eq};
    #[test_only]
    use std::hash::sha2_256;

    const ERROR_U256_TO_FR: u64 = 2001;
    const ERROR_LENGTH_VK: u64 = 2002;
    const ERROR_LENGTH_PROOF: u64 = 2003;
    const ERROR_SPHINX_PROOF_VERSION: u64 = 2004;

    const VK_BYTES_SIZE: u64 = 32;
    const PROOF_CHUNK_BYTE_SIZE: u64 = 32;

    public fun validate_fixture_data(sphinx_proof: vector<u8>, sphinx_vkey: vector<u8>): (vector<u256>, u256) {
        assert!(length(&sphinx_vkey) == VK_BYTES_SIZE, ERROR_LENGTH_VK);
        let proof_length = length(&sphinx_proof);
        assert!(proof_length > 4, ERROR_LENGTH_PROOF);
        assert!((proof_length - 4) % PROOF_CHUNK_BYTE_SIZE == 0, ERROR_LENGTH_PROOF);

        // convert vkey
        let vkey: u256 = bytes_to_uint256(sphinx_vkey);

        // check hardcoded plonk verifier hash
        let expected_version: u256 = 0xa8558442; // corresponds to v1.0.8-testnet artifacts
        let actual_version = slice(&sphinx_proof, 0, 4);
        let actual_version: u256 = bytes_to_uint256(actual_version);
        assert!(expected_version == actual_version, ERROR_SPHINX_PROOF_VERSION);

        // convert proof
        let i = 0;
        let n = (proof_length - 4) / PROOF_CHUNK_BYTE_SIZE;
        let proof_in = vector::empty<u256>();
        while (i < n) {
            let chunk = slice(&sphinx_proof, i * PROOF_CHUNK_BYTE_SIZE + 4, i * PROOF_CHUNK_BYTE_SIZE + PROOF_CHUNK_BYTE_SIZE + 4);
            push_back(&mut proof_in, bytes_to_uint256(chunk));
            i = i + 1;
        };
        (proof_in, vkey)
    }

    public fun powSmall(base: Element<Fr>, exponent: u256): Element<Fr> {
        let result = one<Fr>();
        let input = base;
        let count: u256 = 1;
        let endPoint = exponent + 1;
        while (count < endPoint) {
            if ((exponent & count) > 0) {
                result = mul(&result, &input);
            };
            input = mul(&input, &input);
            count = count + count;
        };
        result
    }

    public fun fr_to_u256(input: Element<Fr>): u256 {
        bytes_to_uint256(serialize<Fr, FormatFrMsb>(&input))
    }

    public fun u256_to_fr(input: u256): Element<Fr> {
        // input needs to be smaller than R_MOD of Bn254 field
        assert!(input < 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001, ERROR_U256_TO_FR);

        let output_bytes = vector::empty<u8>();
        append_value(&mut output_bytes, input, true, 32);
        let output = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&output_bytes));
        output
    }

    public fun u256_to_bytes(input: u256): vector<u8> {
        let output = vector::empty<u8>();
        append_value(&mut output, input, true, 32);
        output
    }

    public fun new_g1(x: u256, y: u256): Element<G1> {
        let output = vector::empty<u8>();
        append_value(&mut output, x, false, 32);
        append_value(&mut output, y, false, 32);
        let output = std::option::extract(&mut deserialize<G1, FormatG1Uncompr>(&output));
        output
    }

    // Considering Ethereum pairing (0x08) precompile format input [a, b, c, d]
    // (see https://gist.github.com/chriseth/f9be9d9391efc5beb9704255a8e2989d#file-snarktest-solidity-L27)
    // in Aptos it should be [b, a, d, c].
    public fun new_g2(a: u256, b: u256, c: u256, d: u256): Element<G2> {
        let output = vector::empty<u8>();
        append_value(&mut output, b, false, 32);
        append_value(&mut output, a, false, 32);
        append_value(&mut output, d, false, 32);
        append_value(&mut output, c, false, 32);
        let output = std::option::extract(&mut deserialize<G2, FormatG2Uncompr>(&output));
        output
    }

    public fun point_acc_mul(g1_mul: Element<G1>, scalar: Element<Fr>, g1_add: Element<G1>): Element<G1> {
        let scalar_multiplication = scalar_mul(&g1_mul, &scalar);
        add(&scalar_multiplication, &g1_add)
    }

    public fun fr_acc_mul(dst: u256, src: u256, scalar: u256): Element<Fr>{
        let tmp = mul(&u256_to_fr(src), &u256_to_fr(scalar));
        let output = add(&tmp, &u256_to_fr(dst));
        output
    }

    public fun get_coordinates(input: Element<G1>): (u256, u256) {
        let input_bytes = serialize<G1, FormatG1Uncompr>(&input);
        let input_x = slice(&input_bytes, 0, 32);
        reverse(&mut input_x);
        let input_y = slice(&input_bytes, 32, 64);
        reverse(&mut input_y);
        (bytes_to_uint256(input_x), bytes_to_uint256(input_y))
    }

    public fun unset_first_bit(input: u256): u256 {
        input & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    }

    // Necessary to make G1 coordinates computed in Move compatible to Ethereum
    public fun prepare_pairing_g1_input(input: Element<G1>, p_modulus: u256): Element<G1> {
        let (x, y) = get_coordinates(input);
        let x = unset_first_bit(x);
        let y = unset_first_bit(y);
        let y = p_modulus - y;
        new_g1(x, y)
    }

    public fun bytes_to_uint256(input: vector<u8>): u256 {
        assert!(length(&input) <= 32, 1);
        let index = 0;

        // do padding
        let padded = vector::empty<u8>();
        while(index < 32 - length(&input)) {
            push_back(&mut padded, 0);
            index = index + 1
        };
        append(&mut padded, input);

        let result: u256 =
            (*vector::borrow(&padded, 31) & 0xFF as u256) |
                (*vector::borrow(&padded, 30) & 0xFF as u256) <<   8 |
                (*vector::borrow(&padded, 29) & 0xFF as u256) <<  16 |
                (*vector::borrow(&padded, 28) & 0xFF as u256) <<  24 |
                (*vector::borrow(&padded, 27) & 0xFF as u256) <<  32 |
                (*vector::borrow(&padded, 26) & 0xFF as u256) <<  40 |
                (*vector::borrow(&padded, 25) & 0xFF as u256) <<  48 |
                (*vector::borrow(&padded, 24) & 0xFF as u256) <<  56 |
                (*vector::borrow(&padded, 23) & 0xFF as u256) <<  64 |
                (*vector::borrow(&padded, 22) & 0xFF as u256) <<  72 |
                (*vector::borrow(&padded, 21) & 0xFF as u256) <<  80 |
                (*vector::borrow(&padded, 20) & 0xFF as u256) <<  88 |
                (*vector::borrow(&padded, 19) & 0xFF as u256) <<  96 |
                (*vector::borrow(&padded, 18) & 0xFF as u256) << 104 |
                (*vector::borrow(&padded, 17) & 0xFF as u256) << 112 |
                (*vector::borrow(&padded, 16) & 0xFF as u256) << 120 |
                (*vector::borrow(&padded, 15) & 0xFF as u256) << 128 |
                (*vector::borrow(&padded, 14) & 0xFF as u256) << 136 |
                (*vector::borrow(&padded, 13) & 0xFF as u256) << 144 |
                (*vector::borrow(&padded, 12) & 0xFF as u256) << 152 |
                (*vector::borrow(&padded, 11) & 0xFF as u256) << 160 |
                (*vector::borrow(&padded, 10) & 0xFF as u256) << 168 |
                (*vector::borrow(&padded,  9) & 0xFF as u256) << 176 |
                (*vector::borrow(&padded,  8) & 0xFF as u256) << 184 |
                (*vector::borrow(&padded,  7) & 0xFF as u256) << 192 |
                (*vector::borrow(&padded,  6) & 0xFF as u256) << 200 |
                (*vector::borrow(&padded,  5) & 0xFF as u256) << 208 |
                (*vector::borrow(&padded,  4) & 0xFF as u256) << 216 |
                (*vector::borrow(&padded,  3) & 0xFF as u256) << 224 |
                (*vector::borrow(&padded,  2) & 0xFF as u256) << 232 |
                (*vector::borrow(&padded,  1) & 0xFF as u256) << 240 |
                (*vector::borrow(&padded,  0) & 0xFF as u256) << 248;

        result
    }

    public fun append_value(preimage: &mut vector<u8>, constant_value: u256, use_reverse: bool, num_bytes_to_append: u64) {
        let v = vector::empty<u8>();
        push_back(&mut v, ((0x00000000000000000000000000000000000000000000000000000000000000ff & constant_value) as u8));
        push_back(&mut v, ((0x000000000000000000000000000000000000000000000000000000000000ff00 & constant_value) >> 8 as u8));
        push_back(&mut v, ((0x0000000000000000000000000000000000000000000000000000000000ff0000 & constant_value) >> 16 as u8));
        push_back(&mut v, ((0x00000000000000000000000000000000000000000000000000000000ff000000 & constant_value) >> 24 as u8));
        push_back(&mut v, ((0x000000000000000000000000000000000000000000000000000000ff00000000 & constant_value) >> 32 as u8));
        push_back(&mut v, ((0x0000000000000000000000000000000000000000000000000000ff0000000000 & constant_value) >> 40 as u8));
        push_back(&mut v, ((0x00000000000000000000000000000000000000000000000000ff000000000000 & constant_value) >> 48 as u8));
        push_back(&mut v, ((0x000000000000000000000000000000000000000000000000ff00000000000000 & constant_value) >> 56 as u8));
        push_back(&mut v, ((0x0000000000000000000000000000000000000000000000ff0000000000000000 & constant_value) >> 64 as u8));
        push_back(&mut v, ((0x00000000000000000000000000000000000000000000ff000000000000000000 & constant_value) >> 72 as u8));
        push_back(&mut v, ((0x000000000000000000000000000000000000000000ff00000000000000000000 & constant_value) >> 80 as u8));
        push_back(&mut v, ((0x0000000000000000000000000000000000000000ff0000000000000000000000 & constant_value) >> 88 as u8));
        push_back(&mut v, ((0x00000000000000000000000000000000000000ff000000000000000000000000 & constant_value) >> 96 as u8));
        push_back(&mut v, ((0x000000000000000000000000000000000000ff00000000000000000000000000 & constant_value) >> 104 as u8));
        push_back(&mut v, ((0x0000000000000000000000000000000000ff0000000000000000000000000000 & constant_value) >> 112 as u8));
        push_back(&mut v, ((0x00000000000000000000000000000000ff000000000000000000000000000000 & constant_value) >> 120 as u8));
        push_back(&mut v, ((0x000000000000000000000000000000ff00000000000000000000000000000000 & constant_value) >> 128 as u8));
        push_back(&mut v, ((0x0000000000000000000000000000ff0000000000000000000000000000000000 & constant_value) >> 136 as u8));
        push_back(&mut v, ((0x00000000000000000000000000ff000000000000000000000000000000000000 & constant_value) >> 144 as u8));
        push_back(&mut v, ((0x000000000000000000000000ff00000000000000000000000000000000000000 & constant_value) >> 152 as u8));
        push_back(&mut v, ((0x0000000000000000000000ff0000000000000000000000000000000000000000 & constant_value) >> 160 as u8));
        push_back(&mut v, ((0x00000000000000000000ff000000000000000000000000000000000000000000 & constant_value) >> 168 as u8));
        push_back(&mut v, ((0x000000000000000000ff00000000000000000000000000000000000000000000 & constant_value) >> 176 as u8));
        push_back(&mut v, ((0x0000000000000000ff0000000000000000000000000000000000000000000000 & constant_value) >> 184 as u8));
        push_back(&mut v, ((0x00000000000000ff000000000000000000000000000000000000000000000000 & constant_value) >> 192 as u8));
        push_back(&mut v, ((0x000000000000ff00000000000000000000000000000000000000000000000000 & constant_value) >> 200 as u8));
        push_back(&mut v, ((0x0000000000ff0000000000000000000000000000000000000000000000000000 & constant_value) >> 208 as u8));
        push_back(&mut v, ((0x00000000ff000000000000000000000000000000000000000000000000000000 & constant_value) >> 216 as u8));
        push_back(&mut v, ((0x000000ff00000000000000000000000000000000000000000000000000000000 & constant_value) >> 224 as u8));
        push_back(&mut v, ((0x0000ff0000000000000000000000000000000000000000000000000000000000 & constant_value) >> 232 as u8));
        push_back(&mut v, ((0x00ff000000000000000000000000000000000000000000000000000000000000 & constant_value) >> 240 as u8));
        push_back(&mut v, ((0xff00000000000000000000000000000000000000000000000000000000000000 & constant_value) >> 248 as u8));

        trim(&mut v, num_bytes_to_append);

        if (use_reverse) {
            reverse(&mut v);
        };

        append(preimage, v);
    }

    #[test]
    public fun test_point_acc_mul() {
        let g1_mul = new_g1(0x143856445caa26db7923454b0352aa2856a40426a61344a62063e2a155a36e90, 0x2602c5e130d1246cbbc88c26b74ea864dcb1dc94bc8128faa4e39fd81ab64e64);
        let scalar = u256_to_fr(0x227968b6d1ad8c5e5098ebdcda749f7ea276621c56e733010a3a0e464f1f8957);
        let g1_add = new_g1(0x1f201aede6e12b30bc9cf21d5e92534ef76d84e88e95eeb772f5a59f65ac7ea1, 0x28f2b25c8172a777d706196a470e604c650372818f2f514efff1e7e76d413a8e);

        let result = point_acc_mul(g1_mul, scalar, g1_add);
        assert!(eq(&result, &new_g1(0x1372be68afe235fcad22b0f5bbee8120b4144cf12e8be05e0fee58b2edaefb99, 0xafc56161d230c677af679bff840f73ebb1695e796d1920dca58cb1dacd0274d5)), 1);
    }

    #[test]
    public fun test_bn254_scalars_addition() {
        // Solidity: addmod
        let a = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"0cbe7095af97c7216c700745a24302c184eeb9a3551de6ecfb2396985cd1dafd"));
        let b = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a"));
        let expected = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"2307eeaad2b5ca260d6537c2ac903e48d0b35cdf0ca4af703ff1c89f0624d117"));
        assert!(eq(&expected, &add(&a, &b)), 1);
    }

    #[test]
    public fun test_bn254_scalars_multiplication() {
        // Solidity: mulmod
        let a = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"0cbe7095af97c7216c700745a24302c184eeb9a3551de6ecfb2396985cd1dafd"));
        let b = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"16497e15231e0304a0f5307d0a4d3b874bc4a33bb786c88344ce3206a952f61a"));
        let expected = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"2032983079d3daf8186a04ab79b8570a1f5226f3e8b30cde5176d84d75f76a61"));
        assert!(eq(&expected, &mul(&a, &b)), 1);
    }

    #[test]
    public fun test_bn254_g1_scalar_multiplication() {
        // Move expects x and y coordinates of the G1 point passed in Little-endian format
        let a = std::option::extract(&mut deserialize<G1, FormatG1Uncompr>(&x"cbdde2db5e9eb445fd2a5f8dd4ed239f13ec042ff60f0f0d125536af01b57300945be08184c177f26a9078c0a3ad2cbb7028632a622e18dd125095c0b3af0c01"));
        let scalar = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"191d3d4743b4d1ce3936a0a668cf6f6450284579dbe266e3645b6764cf24b936"));
        let actual = scalar_mul(&a, &scalar);
        let expected = std::option::extract(&mut deserialize<G1, FormatG1Uncompr>(&x"8ac9160e6c4336c9b387bf1e062b818c2d30f553baf3f9d8bbd9f496c2bf6e10ded5294487a4f92e0257aafc54bc62a121607e41f3b768d42a4a2e8523558009"));
        assert!(eq(&expected, &actual), 1);
    }

    #[test]
    public fun test_bn254_g1_points_addition() {
        // Move expects x and y coordinates of the G1 point passed in Little-endian format
        let a = std::option::extract(&mut deserialize<G1, FormatG1Uncompr>(&x"a37ba777818e3c22b35138da012cb8959d812436a07022921ced72e56ee70006965eb554b0116bc91fb85b1c8740a7a9d5e2b6e71d92b9722c793faa34608322"));
        let b = std::option::extract(&mut deserialize<G1, FormatG1Uncompr>(&x"761a81918388b8152b02f11a06c43dd4468186b351caf8ec1eb05ed47e722d1453d0b9bf1b00f57b14d5f928979cfde421ca39cbfc97b4d596aadb8881256529"));

        let actual = add(&a, &b);
        let expected = std::option::extract(&mut deserialize<G1, FormatG1Uncompr>(&x"69be8ad66ad2f4e45979eeb0eb0f1a4b172d761d7a8a4c4a9d40c1a80851440c92483d53ebbe578662f7a3d803d4c4afb87b1c4f751dcdb74d6acc057b1f3306"));
        assert!(eq(&expected, &actual), 1);
    }

    #[test]
    public fun test_pow_small() {
        let a = std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"0cbe7095af97c7216c700745a24302c184eeb9a3551de6ecfb2396985cd1dafd"));
        let b: u256 = 0x09;

        // odd exponent
        let powered = powSmall(a, b);
        assert!(eq(&powered, &std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"049db9ef0451304702a761fcd3c12d8821bde5d618b0d834916006f5dd77d9ab"))), 1);

        // even exponent
        let b: u256 = 0x08;
        let powered = powSmall(a, b);
        assert!(eq(&powered, &std::option::extract(&mut deserialize<Fr, FormatFrMsb>(&x"2a86bed4464250ee648c70182c717fa685685cd52fe9df6181492d8b568807c6"))), 2);

        // big exponent
        let b: u256 =   0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
        let powered = powSmall(a, b);
        assert!(eq(&powered, &one<Fr>()), 3);
    }

    #[test]
    public fun test_sha256_move_eth_precompile_compatibility() {
        let expected = vector::empty<u8>();
        append_value(&mut expected, 0xdfcbe3edc0a05d7193fd50b1f4f4216d51e1468886834251204283f93278b675, true, 32);

        let preimage = vector::empty<u8>();
        append_value(&mut preimage, 0x67616d6d61, true, 32);

        assert!(expected == sha2_256(preimage), 1);
    }

    #[test]
    public fun test_32bytes_u256_conversion() {
        let beta = bytes_to_uint256(x"42fc83c6f494936df5a8d6d66f7b1c92e8f9e3b4f59653a03260e3b61590e031");
        assert!(beta == 0x42fc83c6f494936df5a8d6d66f7b1c92e8f9e3b4f59653a03260e3b61590e031, 1);
    }
}
