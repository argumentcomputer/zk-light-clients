#[cfg(test)]
mod tests {
    use kadena_programs::BLOCK_HEADER_HASHING_PROGRAM;
    use sphinx_sdk::utils::setup_logger;
    use sphinx_sdk::{ProverClient, SphinxStdin};

    #[test]
    fn sphinx_execute_test() {
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
    fn sphinx_stark_proving_test() {
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
    fn sphinx_snark_proving_test() {
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
