script {
    use plonk_verifier_addr::plonk_verifier;
    use plonk_verifier_addr::utilities::{validate_fixture_data};
    use std::vector::length;

    const ERROR_LENGTH_VK: u64 = 3001;
    const ERROR_LENGTH_PROOF: u64 = 3002;
    const ERROR_PROOF_VERSION: u64 = 3003;

    fun run_verification<T1, T2>(
        _account: signer,
        vkey_: vector<u8>,
        public_values: vector<u8>,
        proof_: vector<u8>,
    ) {
        // we do not perform input validation of public_values since while core verification it is hashed,
        // and if hash is invalid, core verification will simply fail
        assert!(length(&vkey_) == 32, ERROR_LENGTH_VK);
        assert!((length(&proof_) - 4) % 32 == 0, ERROR_LENGTH_PROOF);

        let (proof, vkey) = validate_fixture_data(proof_, vkey_);

        plonk_verifier::verify(proof, vkey, public_values);
    }
}
