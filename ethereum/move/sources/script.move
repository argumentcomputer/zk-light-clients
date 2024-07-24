script {
    use plonk_verifier_addr::plonk_verifier;
    use plonk_verifier_addr::utilities::{bytes_to_uint256};
    use std::vector::{length, slice, push_back};
    use std::vector;

    const ERROR_LENGTH_VK: u64 = 3001;
    const ERROR_LENGTH_RAW_PUBLIC_INPUTS: u64 = 3002;
    const ERROR_LENGTH_PROOF: u64 = 3003;

    fun run_verification<T1, T2>(
        _account: signer,
        vkey_: vector<u8>,
        public_values: vector<u8>,
        proof_: vector<u8>,
    ) {
        assert!(length(&vkey_) == 32, ERROR_LENGTH_VK);
        assert!(length(&proof_) % 32 == 0, ERROR_LENGTH_PROOF);

        // convert vkey
        let vkey: u256 = bytes_to_uint256(vkey_);

        // convert proof
        let i = 0;
        let n = length(&proof_) / 32;
        let proof = vector::empty<u256>();
        while (i < n) {
            let chunk = slice(&proof_, i * 32, i * 32 + 32);
            push_back(&mut proof, bytes_to_uint256(chunk));
            i = i + 1;
        };

        plonk_verifier::verify(proof, vkey, public_values);
    }
}
