#[cfg(test)]
mod tests {
    use kadena_programs::{bench::SHA512_256_PROGRAM, BLOCK_HEADER_HASHING_PROGRAM};
    use sha2::{Digest, Sha512Trunc256};
    use sphinx_sdk::utils::setup_logger;
    use sphinx_sdk::{ProverClient, SphinxStdin};

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
