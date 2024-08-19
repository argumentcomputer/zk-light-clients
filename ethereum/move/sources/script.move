script {
    use plonk_verifier_addr::plonk_verifier;
    use plonk_verifier_addr::utilities::{bytes_to_uint256};
    use std::vector::{length, slice, push_back};
    use std::vector;

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

        // convert vkey
        let vkey: u256 = bytes_to_uint256(vkey_);

        // check hardcoded plonk verifier hash
        let expected_verifier_hash: u256 = 0xa8558442; // corresponds to v1.0.8-testnet artifacts
        let verifier_hash_header = slice(&proof_, 0, 4);
        let verifier_hash: u256 = bytes_to_uint256(verifier_hash_header);
        assert!(verifier_hash == expected_verifier_hash, ERROR_PROOF_VERSION);

        // convert proof
        let i = 0;
        let n = (length(&proof_) - 4) / 32;
        let proof = vector::empty<u256>();
        while (i < n) {
            // offset by 4 to skip the version header
            let chunk = slice(&proof_, 4 + i * 32, 4 + i * 32 + 32);
            push_back(&mut proof, bytes_to_uint256(chunk));
            i = i + 1;
        };

        plonk_verifier::verify(proof, vkey, public_values);
    }
}
