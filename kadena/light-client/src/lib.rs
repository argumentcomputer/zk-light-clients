#[cfg(test)]
mod tests {
    use kadena_programs::{bench::SHA512_256_PROGRAM, BLOCK_HEADER_HASHING_PROGRAM};
    use sha2::{Digest, Sha512Trunc256};
    use sphinx_sdk::utils::setup_logger;
    use sphinx_sdk::{ProverClient, SphinxStdin};

    fn sha512_extend(w: &mut [u64; 80]) {
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
    }

    fn sha512_compress(state: &mut [u64; 8], w: &[u64; 80]) {
        let k: [u64; 80] = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817,
        ];

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    fn sha512_256_block(block: [u64; 16]) -> [u64; 4] {
        // Initial H constants precomputed for SHA512_256
        let mut state: [u64; 8] = [
            0x22312194fc2bf72c,
            0x9f555fa3c84c64c2,
            0x2393b86b6f53b151,
            0x963877195940eabd,
            0x96283ee2a88effe3,
            0xbe5e1e2553863992,
            0x2b0199fc2c85b8aa,
            0x0eb72ddc81c52ca2,
        ];

        let mut w = [0u64; 80];
        w[..16].copy_from_slice(&block);

        sha512_extend(&mut w);
        sha512_compress(&mut state, &w);

        [state[0], state[1], state[2], state[3]]
    }

    #[test]
    fn test_one_block_sha256_256_hashing() {
        let input: [u64; 16] = [
            0x8000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ];

        // Test vector from: https://en.wikipedia.org/wiki/SHA-2
        let expected_hash: [u64; 4] = [
            0xc672b8d1ef56ed28,
            0xab87c3622c511406,
            0x9bdd3ad7b8f97374,
            0x98d0c01ecef0967a,
        ];
        let actual_hash = sha512_256_block(input);
        assert_eq!(expected_hash, actual_hash);
    }

    #[test]
    fn test_sha512_256_sphinx_program_execute() {
        fn test_inner(input: &[u8]) {
            let hash = Sha512Trunc256::digest(input);
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&hash);

            let prover = ProverClient::new();
            let mut stdin = SphinxStdin::new();
            stdin.write(&input.to_vec());
            let (mut public_values, _) = prover.execute(SHA512_256_PROGRAM, stdin).run().unwrap();
            let mut actual = vec![1u8; 32];
            public_values.read_slice(&mut actual);

            assert_eq!(actual, expected);
        }

        test_inner(Vec::<u8>::new().as_slice());
        test_inner(vec![0u8; 100].as_slice());
        test_inner(vec![1u8; 200].as_slice());
        test_inner(vec![2u8; 300].as_slice());
    }

    #[test]
    #[ignore]
    fn test_sha512_256_sphinx_program_prove_stark() {
        setup_logger();

        let prover = ProverClient::new();
        let mut stdin = SphinxStdin::new();
        stdin.write(&Vec::<u8>::new());

        let (pk, vk) = prover.setup(SHA512_256_PROGRAM);
        let proof = prover.prove(&pk, stdin).core().run().unwrap();
        prover.verify(&proof, &vk).unwrap();
    }

    #[test]
    #[ignore]
    fn test_sha512_256_sphinx_program_prove_snark() {
        setup_logger();

        let prover = ProverClient::new();
        let mut stdin = SphinxStdin::new();
        stdin.write(&Vec::<u8>::new());

        let (pk, vk) = prover.setup(SHA512_256_PROGRAM);
        let proof = prover.prove(&pk, stdin).plonk().run().unwrap();
        prover.verify(&proof, &vk).unwrap();
    }

    #[test]
    fn test_kadena_block_header_hashing_program_execute() {
        let header = b"AAAAAAAAAADagen7WaIFAASBaVOSlhojqQjImJ0F2PR258lozvJLjkLfXfsEIjPCAwAAAAAAHHEJ8CfvcweMTfvSMBYlXLWv0v25Mt-4bK3RUi_L6lsBAAAAi0pTBul2AUh0jWNPs2LXCdc_sgEyFK01O_bmHgDwkWAIAAAAYzOtui7Ns_-SQp472GrIlRUmIl9UsDagsuZ-Xuzf_L3__________________________________________4dF0GK2zmpsHFv5NYbuvc0pyhXfXwxxJRM0uvq8InFUAwAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAACH1lqeSNBQAAAAAAAAAAAJhcOUndKMtEn5_aPlk_LbLgU-vK_gpvrf14eFWrgEFW".to_vec();

        let mut stdin = SphinxStdin::new();
        stdin.write(&header);

        let prover = ProverClient::new();
        prover
            .execute(BLOCK_HEADER_HASHING_PROGRAM, stdin)
            .run()
            .unwrap();
    }

    #[test]
    #[ignore]
    fn test_kadena_block_header_hashing_program_prove_stark() {
        setup_logger();

        let header = b"AAAAAAAAAADagen7WaIFAASBaVOSlhojqQjImJ0F2PR258lozvJLjkLfXfsEIjPCAwAAAAAAHHEJ8CfvcweMTfvSMBYlXLWv0v25Mt-4bK3RUi_L6lsBAAAAi0pTBul2AUh0jWNPs2LXCdc_sgEyFK01O_bmHgDwkWAIAAAAYzOtui7Ns_-SQp472GrIlRUmIl9UsDagsuZ-Xuzf_L3__________________________________________4dF0GK2zmpsHFv5NYbuvc0pyhXfXwxxJRM0uvq8InFUAwAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAACH1lqeSNBQAAAAAAAAAAAJhcOUndKMtEn5_aPlk_LbLgU-vK_gpvrf14eFWrgEFW".to_vec();

        let mut stdin = SphinxStdin::new();
        stdin.write(&header);

        let prover = ProverClient::new();
        let (pk, vk) = prover.setup(BLOCK_HEADER_HASHING_PROGRAM);
        let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
        prover.verify(&proof, &vk).unwrap();
    }

    #[test]
    #[ignore]
    fn test_kadena_block_header_hashing_program_prove_snark() {
        setup_logger();

        let header = b"AAAAAAAAAADagen7WaIFAASBaVOSlhojqQjImJ0F2PR258lozvJLjkLfXfsEIjPCAwAAAAAAHHEJ8CfvcweMTfvSMBYlXLWv0v25Mt-4bK3RUi_L6lsBAAAAi0pTBul2AUh0jWNPs2LXCdc_sgEyFK01O_bmHgDwkWAIAAAAYzOtui7Ns_-SQp472GrIlRUmIl9UsDagsuZ-Xuzf_L3__________________________________________4dF0GK2zmpsHFv5NYbuvc0pyhXfXwxxJRM0uvq8InFUAwAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAACH1lqeSNBQAAAAAAAAAAAJhcOUndKMtEn5_aPlk_LbLgU-vK_gpvrf14eFWrgEFW".to_vec();

        let mut stdin = SphinxStdin::new();
        stdin.write(&header);

        let prover = ProverClient::new();
        let (pk, vk) = prover.setup(BLOCK_HEADER_HASHING_PROGRAM);
        let proof = prover.prove(&pk, stdin).plonk().run().unwrap();
        prover.verify(&proof, &vk).unwrap();
    }
}
