module plonk_verifier_addr::wrapper {
    use std::signer;
    use plonk_verifier_addr::plonk_verifier;
    use std::vector::{length, slice, reverse};
    use plonk_verifier_addr::utilities::bytes_to_uint256;
    use std::string::utf8;
    use plonk_verifier_addr::utilities;

    const ERROR_COMMITTEE_CHANGE: u64 = 4004;
    const ERROR_INCLUSION: u64 = 4005;
    const ERROR_COMMITTEE_CHANGE_UNEXPECTED_PUBLIC_VALUES: u64 = 4006;
    const ERROR_INCLUSION_UNEXPECTED_PUBLIC_VALUES: u64 = 4007;

    // block height (8 bytes) |
    // signer_sync_committee (32 bytes) |
    // updated_sync_committee (32 bytes) |
    // next_sync_committee (32 bytes)
    const COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES: u64 = 104;

    // block height (8 bytes) |
    // signer_sync_committee (32 bytes) |
    // eip1186_proof_address (20 bytes) |
    // eip1186_proof_address_hash (32 bytes) |
    // eip1186_proof_length (8 bytes) |
    // one merkle tree key (8 bytes length prefix + at least 1 byte) |
    // one merkle tree value (8 bytes length prefix + at least 1 byte)
    const INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES: u64 = 118;

    const BLOCK_HEIGHT_BYTE_SIZE: u64 = 8;
    const COMMITTEE_HASH_BYTE_SIZE: u64 = 32;
    const EIP1186_PROOF_ADDRESS_BYTE_SIZE: u64 = 20;
    const EIP1186_PROOF_ADDRESS_HASH_BYTE_SIZE: u64 = 32;
    const U64_ENCODED_BYTE_SIZE: u64 = 8;

    struct Hashes has drop, store, key {
        current_hash: u256,
        next_hash: u256,
    }

    fun publish(account: &signer, current_hash: u256, next_hash: u256) {
        // only owner of 'Hashes' resource can actually publish it
        move_to(account, Hashes {
            current_hash,
            next_hash,
        })
    }

    #[view]
    public fun get_current_hash_stored(addr: address): u256 acquires Hashes {
        borrow_global<Hashes>(addr).current_hash
    }

    #[view]
    public fun get_next_hash_stored(addr: address): u256 acquires Hashes {
        borrow_global<Hashes>(addr).next_hash
    }

    fun update_current_hash(account: &signer, hash: u256) acquires Hashes {
        // only owner of 'Hashes' resource can update it
        let c = move_from<Hashes>(signer::address_of(account));
        c.current_hash = hash;
        move_to(account, c)
    }

    fun update_next_hash(account: &signer, hash: u256) acquires Hashes {
        // only owner of 'Hashes' resource can update it
        let c = move_from<Hashes>(signer::address_of(account));
        c.next_hash = hash;
        move_to(account, c)
    }

    fun delete(account: &signer): (u256, u256) acquires Hashes {
        // only owner of 'Hashes' resource can delete it
        let c = move_from<Hashes>(signer::address_of(account));
        let Hashes { current_hash: hash_1, next_hash: hash_2 } = c;
        (hash_1, hash_2)
    }

    #[view]
    public fun exists_at(addr: address): bool {
        exists<Hashes>(addr)
    }

    public fun committee_change_event_processing(a: &signer, vkey: vector<u8>, proof: vector<u8>, public_values: vector<u8>) acquires Hashes {
        // we know definitely the expected length of public values for committee change event
        assert!(length(&public_values) == COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES, ERROR_COMMITTEE_CHANGE_UNEXPECTED_PUBLIC_VALUES);

        let (proof_in, vkey) = utilities::validate_fixture_data(proof, vkey);

        // execute core verification
        plonk_verifier::verify(proof_in, vkey, public_values);

        // post processing
        let offset = 0;
        let block_height = slice(&public_values, offset, BLOCK_HEIGHT_BYTE_SIZE);
        offset = offset + BLOCK_HEIGHT_BYTE_SIZE;

        let signer_sync_committee = bytes_to_uint256(slice(&public_values, offset, offset + COMMITTEE_HASH_BYTE_SIZE));
        offset = offset + COMMITTEE_HASH_BYTE_SIZE;

        let updated_sync_committee = bytes_to_uint256(slice(&public_values, offset, offset + COMMITTEE_HASH_BYTE_SIZE));
        offset = offset + COMMITTEE_HASH_BYTE_SIZE;

        let next_sync_committee = bytes_to_uint256(slice(&public_values, offset, offset + COMMITTEE_HASH_BYTE_SIZE));

        let curr_hash_stored = get_current_hash_stored(signer::address_of(a));
        let next_hash_stored = get_next_hash_stored(signer::address_of(a));

        if ((signer_sync_committee == curr_hash_stored) || (signer_sync_committee == next_hash_stored)) {
            // allow updating stored values as soon as 'signer_sync_committee' is in storage
            update_current_hash(a, updated_sync_committee);
            update_next_hash(a, next_sync_committee);

            aptos_std::debug::print(&utf8(b"committee change is successful. Block height is:"));
            aptos_std::debug::print(&block_height);
        } else {
            assert!(false, ERROR_COMMITTEE_CHANGE);
        }
    }

    public fun inclusion_event_processing(a: &signer, vkey: vector<u8>, proof: vector<u8>, public_values: vector<u8>) acquires Hashes {
        // we know only minimal acceptable length of public values in inclusion event, when EIP1186 proof contains 1 key/value pair
        assert!(length(&public_values) >= INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES, ERROR_INCLUSION_UNEXPECTED_PUBLIC_VALUES);

        let (proof_in, vkey) = utilities::validate_fixture_data(proof, vkey);

        // execute core verification
        plonk_verifier::verify(proof_in, vkey, public_values);

        // post processing
        let offset = 0;
        let block_height = slice(&public_values, offset, BLOCK_HEIGHT_BYTE_SIZE);
        offset = offset + BLOCK_HEIGHT_BYTE_SIZE;

        let signer_sync_committee = bytes_to_uint256(slice(&public_values, offset, offset + COMMITTEE_HASH_BYTE_SIZE));
        offset = offset + COMMITTEE_HASH_BYTE_SIZE;

        let eip1186_proof_address = slice(&public_values, offset, offset + EIP1186_PROOF_ADDRESS_BYTE_SIZE);
        offset = offset + EIP1186_PROOF_ADDRESS_BYTE_SIZE;

        let eip1186_proof_address_hash = slice(&public_values, offset, offset + EIP1186_PROOF_ADDRESS_HASH_BYTE_SIZE);
        offset = offset + EIP1186_PROOF_ADDRESS_HASH_BYTE_SIZE;

        let eip1186_proof_length = slice(&public_values, offset, offset + U64_ENCODED_BYTE_SIZE);
        offset = offset + U64_ENCODED_BYTE_SIZE;

        let curr_hash_stored = get_current_hash_stored(signer::address_of(a));
        let next_hash_stored = get_next_hash_stored(signer::address_of(a));

        if ((signer_sync_committee == curr_hash_stored) || (signer_sync_committee == next_hash_stored)) {
            aptos_std::debug::print(&utf8(b"inclusion is successful. Transferring funds is allowed."));
            aptos_std::debug::print(&utf8(b"block height is:"));
            aptos_std::debug::print(&block_height);
            aptos_std::debug::print(&utf8(b"EIP1186 proof address is:"));
            aptos_std::debug::print(&eip1186_proof_address);
            aptos_std::debug::print(&utf8(b"EIP1186 proof address hash is:"));
            aptos_std::debug::print(&eip1186_proof_address_hash);
            aptos_std::debug::print(&utf8(b"EIP1186 proof size is:"));
            aptos_std::debug::print(&eip1186_proof_length);
            aptos_std::debug::print(&utf8(b"printing up to 5 first key/value pairs:"));

            aptos_std::debug::print(&utf8(b"---------------------------------------"));
            let key_value_pairs_amount = eip1186_proof_length;
            reverse(&mut key_value_pairs_amount);
            let key_value_pairs_amount = bytes_to_uint256(key_value_pairs_amount);

            let i = 0;
            while (i < key_value_pairs_amount) {
                let key_length = slice(&public_values, offset, offset + U64_ENCODED_BYTE_SIZE);
                offset = offset + U64_ENCODED_BYTE_SIZE;

                reverse(&mut key_length);

                let key_size = (bytes_to_uint256(key_length) as u64);
                let key = slice(&public_values, offset, offset + key_size);
                offset = offset + key_size;

                let value_length = slice(&public_values, offset, offset + U64_ENCODED_BYTE_SIZE);
                offset = offset + U64_ENCODED_BYTE_SIZE;

                reverse(&mut value_length);

                let value_size = (bytes_to_uint256(value_length) as u64);
                let value = slice(&public_values, offset, offset + value_size);
                offset = offset + value_size;

                if (i < 5) {
                    aptos_std::debug::print(&utf8(b"key:"));
                    aptos_std::debug::print(&key);
                    aptos_std::debug::print(&utf8(b"value:"));
                    aptos_std::debug::print(&value);
                };
                i = i + 1;
            };
            aptos_std::debug::print(&utf8(b"---------------------------------------"));
        } else {
            assert!(false, ERROR_INCLUSION);
        }
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_storage_flow(a: signer) acquires Hashes {
        publish(&a, InitialTestHash1, InitialTestHash2);
        assert!(exists_at(signer::address_of(&a)), 1);

        update_current_hash(&a, SignerSyncCommitteeHashH29);
        update_next_hash(&a, UpdatedSyncCommitteeHashH30);

        let hash_1 = get_current_hash_stored(signer::address_of(&a));
        let hash_2 = get_next_hash_stored(signer::address_of(&a));

        assert!(hash_1 == SignerSyncCommitteeHashH29, 2);
        assert!(hash_2 == UpdatedSyncCommitteeHashH30, 3);

        delete(&a);
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_committee_change_is_allowed(a: signer) acquires Hashes {
        publish(&a, InitialTestHash1, SignerSyncCommitteeHashH29);

        committee_change_event_processing(&a, EpochChangeVk, EpochChangeProof, EpochChangePublicValues);

        let (left, right) = delete(&a);
        // Committee change happened (since SignerSyncCommitteeHashH29 was in storage)
        assert!(left == UpdatedSyncCommitteeHashH30,  1);
        assert!(right == NextSyncCommitteeHashH31 , 2);
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_committee_change_is_allowed_too(a: signer) acquires Hashes {
        publish(&a, SignerSyncCommitteeHashH29, InitialTestHash2);

        committee_change_event_processing(&a, EpochChangeVk, EpochChangeProof, EpochChangePublicValues);

        let (left, right) = delete(&a);
        // Committee change happened (since SignerSyncCommitteeHashH29 was in storage)
        assert!(left == UpdatedSyncCommitteeHashH30,  1);
        assert!(right == NextSyncCommitteeHashH31 , 2);
    }

    #[test(a = @plonk_verifier_addr)]
    #[expected_failure(abort_code = ERROR_COMMITTEE_CHANGE)]
    public fun test_committee_change_is_not_allowed(a: signer) acquires Hashes {
        publish(&a, InitialTestHash1, InitialTestHash2);

        // panics, since SignerSyncCommitteeHashH29 was NOT in storage initially
        committee_change_event_processing(&a, EpochChangeVk, EpochChangeProof, EpochChangePublicValues);
    }


    #[test(a = @plonk_verifier_addr)]
    public fun test_inclusion_is_allowed(a: signer) acquires Hashes {
        publish(&a, ValidSignerSyncCommitteeHashInclusion, InitialTestHash2);
        // doesn't panic, since SignerSyncCommitteeHashH29 is in storage
        inclusion_event_processing(&a, InclusionVk, InclusionProof, InclusionPublicValues);

        delete(&a);
    }


    #[test(a = @plonk_verifier_addr)]
    public fun test_inclusion_is_allowed_too(a: signer) acquires Hashes {
        publish(&a, InitialTestHash1, ValidSignerSyncCommitteeHashInclusion);
        // doesn't panic, since SignerSyncCommitteeHashH29 is in storage
        inclusion_event_processing(&a, InclusionVk, InclusionProof, InclusionPublicValues);

        delete(&a);
    }

    #[test(a = @plonk_verifier_addr)]
    #[expected_failure(abort_code = ERROR_INCLUSION)]
    public fun test_inclusion_is_not_allowed(a: signer) acquires Hashes {
        publish(&a, InitialTestHash1, InitialTestHash2);
        // panics, since SignerSyncCommitteeHashH29 is NOT in storage
        inclusion_event_processing(&a, InclusionVk, InclusionProof, InclusionPublicValues);
    }

    const InitialTestHash1: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    const InitialTestHash2: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    const ValidSignerSyncCommitteeHashInclusion: u256 = 0x0969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c9;
    const SignerSyncCommitteeHashH29: u256 = 0x5d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f988050;
    const UpdatedSyncCommitteeHashH30: u256 = 0x85382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c4682;
    const NextSyncCommitteeHashH31: u256 = 0x5ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf;

    const EpochChangeVk: vector<u8> = x"00c55464e91190f7548e4355c11cc43c1187f73cb1547a37aba0e6a1760a11d0";
    const EpochChangePublicValues: vector<u8> = x"e0e58f00000000005d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f98805085382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c46825ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf";
    const EpochChangeProof: vector<u8> = x"7f8918df23025e88161c019ff27e04f984c221805a312ab50a40e4ffc095304dd274edf001cf919dce83c4565ed87bddcecd0de5efcff44832214c4428fc85db314f74cc116a37650a3c8ec2cddb3270a5a81b8a5c461c0b179ca462cc6407e2de6f911728f57555f4ec15b460bd62206c7c36aecee7c9ba7f87575fbcb15084418e69e821da7d5807075cadb6b29d4dadb11ca754e11d8abb7536465592e3b36a7fecfb230d478d78fb5406b560fd9f1fc6ba762c153442666f286c980fa809a752c51109c6fcdfe638c63fcaa208fff939ab00a867bb0dca33350a17444c55d8d3eab401bb5aa5200a28d2ac7c88e9201050ab6a671991761c91cdd4cecb5350c397b218e9eecf39ae24cbf930ef731a6e79f36480590bf6097412f715074412a815040b0ccbf8d9be6e12bcbb49bd6958061ce8a676d742ea61058f163ccfdba611620cc7e460a730db040b38ade6ae55b26e736c4dedcc3d87cd573338b31dd0fbad18d4f0438c93c5e7511465ea3388f5eea716bc99c4cedb7a8a34df0c8ad11cd917de63a7e7174d001ca63f6b9350ab6e5a5b269b12b541711a749f5dd635507701514400cad1b873716b92d3294dba99bc53cbb8f5336bc5666eb014f2fd63c31cd7d03ef4c8570db2f8f42d972ef9ae359c6ae216086237068cdb7788329f270e9fe5a5ea6e808c9662af69e30e76ce65f3ce8073efe405dbf0195ed610ff2b10b8c3eb43b08c018d5181e12cc1f1dff887a04a33c1d0cdc970dbfecfd97e842e2c13e50e5ea338689f2e7c8edf1a1e159f933f634ddfe9f0fe7c7068ec3e7e10d13b39a10369904e33b16d8c88d8b3f9928826ddb98ec62faf697b75ecb49b18d022ef11c3e32741c637f0bc430ae2ff1ad0010164d57f54351ab44e6f2c8604bf33da92855f19ae9b2d41d8da89d0dbc04da9c5201eedda6408785f3e65820a0ee6a5f48ab041147a1408328ee862c4cedd53f71864c78a6b46ba1e65ef8918a6b2b4823221568912f7267baaa5c5a48273f746ec9bae5afd02464871ea09246c30c4c93833da218b1f4b538c7c0226f79611bfca8b78f7431607512933241f50b8c7e58b44d5b5fb68820a470f2551a4d7395be1a4fb0cf787ddd68853db20aafbdff8092c44fcbb79aae0b53d8382cdf41806e55a3432b4e25ec0b9e3d01202c537f05c19dd05063e85b550f4b1d5f06af18b0ed190fead7fd7813788d5";

    const InclusionVk: vector<u8> = x"00d6b0922b33f4a88cac7a71b76e025fa0dfb9b3a2e74e009bd511db5688bd3d";
    const InclusionPublicValues: vector<u8> = x"e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba010000000000000080";
    const InclusionProof: vector<u8> = x"7f8918df24861767a7e453f220f9a2cec1a9c1ba67cb734c50fe292d8a8cbf475f4ecdd417e47908ac676f8310850863c5d558f7f4eec2c8ba1388cc944932a3cf5c371423246685f0aa842f789403288b02dc412a7430eb516b4e8a7e99b1193d32c04b0612df3654f74d051e3e9c24c7be8f34dd570fbf252919dd18243054d5f172550166587515cf6e2ca1292df05941e075f331b3746e60f89f185317007541fdd62c6fe406a14b736020653dcca451f63072f0425ca36dfc832021016821836b9d1c15b06039d70b291574e22c8a20bd7fbae0a72d1c57f092a1f03a26489adf7c234247c6fae957f1ab8e1975c6df1c959ed81a6fc53d523b7969312e5ca2e8d417ba62b8c5f641cec7d6b237ce9fe9f86ce149d31a6329446dce84a21a11cac12800635f363851471dafc379afaefe984351ffabc891a4db80cda0ad9f5cc69a2b5401747be4b3b86204e611f1213a68d41c55cb1e1770a8ab6c4992abec43d7180e0f1fa44c0a5377f6c0ad11120026e4edfbf7fd00084adedd9d88204578bd17c31c5af075458aa0e56d90190c0fc70c70a55ec4a4159baa6873e2fb61089710d52d1f5c8b4ef6121240eceb465540426ea03db93375958522ad6b0b67137d2e455d147a32298f2f46d6fac9ade31b4dc3484a41bfeb9b5c47f1b90b94b75719f77f014c99f7cc23f099cb3ed4d7d9711e30287ced98c4f94b6d9b036073db1c0ed6b8ed155efc8258b39baa46c9e11e480b22670c6da62388eb7af544fa6c18dfed0be8fda5d1e78fab2f7e75b7e1a0af71cff33303e4fe7a64d358cdc0460a81acc9430df6597682a020b2912aeca5bedf2c3e3104b154bd153f1e1da50a163dabc98c40027c88579514f54236520d4b40ede0214c04cfece063bb999a630874ec6b6dbf1a62658fb5e021462914f5371bda976a6af43e44c444039a772817df40bc7d03e0d476be417b10cb978b27f0fb1038ce5b602952eec70d9157f70ab0d26d6acb3a0b1047585dba494d8279e740efdfe7a042c6108bcc7baca7b91dfb390967cd9cb41e5302e1adfaf5bff0975a893df88a492c738b2bbea1c600209f9559f36d4ca29487ef7a1a6aeee4bb298e647bc30437f4600764001cfb92031d6f99499cbc8a55a3629abed1d232c35a6f362c23cc2724f74b98fa11300c2fe8a790c98d3cba19dd001c8d0f5cff70ae5fff32da4bc3f60600cde5388adf";
}
