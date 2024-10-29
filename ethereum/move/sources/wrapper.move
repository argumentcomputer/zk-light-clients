module plonk_verifier_addr::wrapper {
    use std::signer;
    use plonk_verifier_addr::plonk_verifier_core;
    use std::vector::{length, slice, reverse};
    use plonk_verifier_addr::utilities_core::bytes_to_uint256;
    use std::string::utf8;
    use plonk_verifier_addr::utilities_core;

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

    public fun committee_change_event_processing(
        a: &signer,
        vkey: vector<u8>,
        proof: vector<u8>,
        public_values: vector<u8>
    ) acquires Hashes {
        // we know definitely the expected length of public values for committee change event
        assert!(
            length(&public_values) == COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES,
            ERROR_COMMITTEE_CHANGE_UNEXPECTED_PUBLIC_VALUES
        );

        let (proof_in, vkey) = utilities_core::validate_fixture_data(proof, vkey);

        // execute core verification
        plonk_verifier_core::verify(proof_in, vkey, public_values);

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

    public fun inclusion_event_processing(
        a: &signer,
        vkey: vector<u8>,
        proof: vector<u8>,
        public_values: vector<u8>
    ) acquires Hashes {
        // we know only minimal acceptable length of public values in inclusion event, when EIP1186 proof contains 1 key/value pair
        assert!(
            length(&public_values) >= INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES,
            ERROR_INCLUSION_UNEXPECTED_PUBLIC_VALUES
        );

        let (proof_in, vkey) = utilities_core::validate_fixture_data(proof, vkey);

        // execute core verification
        plonk_verifier_core::verify(proof_in, vkey, public_values);

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
        assert!(left == UpdatedSyncCommitteeHashH30, 1);
        assert!(right == NextSyncCommitteeHashH31, 2);
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_committee_change_is_allowed_too(a: signer) acquires Hashes {
        publish(&a, SignerSyncCommitteeHashH29, InitialTestHash2);

        committee_change_event_processing(&a, EpochChangeVk, EpochChangeProof, EpochChangePublicValues);

        let (left, right) = delete(&a);
        // Committee change happened (since SignerSyncCommitteeHashH29 was in storage)
        assert!(left == UpdatedSyncCommitteeHashH30, 1);
        assert!(right == NextSyncCommitteeHashH31, 2);
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

    // From epoch_change fixture
    const SignerSyncCommitteeHashH29: u256 = 0x5d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f988050;
    const UpdatedSyncCommitteeHashH30: u256 = 0x85382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c4682;
    const NextSyncCommitteeHashH31: u256 = 0x5ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf;
    const EpochChangeVk: vector<u8> = x"00de53d6fe5e4e43f950fbc1f6b2c0f9c172097ad7263ab913241267b29d03f2";
    const EpochChangePublicValues: vector<u8> = x"e0e58f00000000005d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f98805085382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c46825ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf";
    const EpochChangeProof: vector<u8> = x"cabf0c6723c9292510933fcf2bf8068ac7a7df0022f5f4de8d5d2547a0ffa1e09c965506035bdd8906864ea3ee70f6cd44d7726c1975c17ac26a744a26100f54aecf87691fbd062b17c8786fd01afcab4809ca01ec97bedabfb2c0c3dffa6e8b6926bfbf00ddc730f359bbfede7c778a19994db0dcca79ffefb97ca8ae7ccd391661818802eeb6a8a839ac6339f52a5d503c945bd1923a63162cb5e5d193a3bd3d93885317e5383a852de3602b59cc1626a210c2c17831227bf04d036618c4bd998549fc257d696d0c245f9ddfeae21bfef158f5ce3307ca53915cd2d3c5ca194207610222b636714862f4c75e8ee084a2b435e86f0924736b09db0332bc67aa7386d5b812f789e02e1383510307505163a74529a8e72242585f4a2a5e512a17248920f12fe57ebf790f8a0c076abe5d978534510b1a5c3006d484fde8f916aeb631f2b603cab349b7b75da20b80e732d758636fbb7bd5371a22bc23ce4509ef46a5839d2d981fbbccb49552c991e35751d9f5fe38eddba89c1d24d1147c02ea50ac3e4f193252b93c2dfa0d5008ab9016ec37fdde3f6e12ce731c9a46973e96be177bb824b78f5c7dc98df27c67b58e4fd7e328516be7a59680cc8d1cbf0d6f04837b841269739001457c3e39f54a963a7b389bfa9916002ef7343fb2666b0559a3f28d14739992620afec9540e3bea43dbcc23c52ab340891ef46f54fb279326ee14de1e38f5bfb70078175fb00b265f6c65448a117446a59ec0c8e98d2e9ba87e63651903a3c4fddb86c20966fd401cc2fded97f0b952beb52eb139cdae175a216dcf0e127c7d4a0db0d81f53e7ada46bc252cb683ba15497e2b8b85ae4924d547db40f66b78c215b2e821135a29bd7d8e17568a895af9629941d9af2bd13fbb15cff111517037995be761c82b822884c74388640bc9bda86619c1cafa15f750074bb0d03a4defc4d4ff6879d5644a35823304f118e4dcf254b1bdf4160b58abf20a20c5f1bc02ac2533d24925a522a89e81dc88299b4ed6a49b5cede98f460483acc27b7d95459c480261c9d4a770b5bbed6258568688b2e939d6efc0ef578150abf1d1dac6f4293d97b7d9e5f06aee3059804a21573415eb2d2af7e32716d410b1711a8174dc28da7738268e83470e506ed7078ad33cf41617176e3d711834ce19b07d0f2865631b0870bd1a2107fc9a3f491ad7792c93d329e4992a95deb75722d";

    // From inclusion fixture
    const ValidSignerSyncCommitteeHashInclusion: u256 = 0x0969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c9;
    const InclusionVk: vector<u8> = x"00deddfe90263f93c03e88dc9c33603f3ea0493b2af5da7e37d515794958bbb7";
    const InclusionPublicValues: vector<u8> = x"e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba010000000000000080";
    const InclusionProof: vector<u8> = x"cabf0c6721224ac1ac5a130cc326c41365b45cd128c3d654320d66300d570401398387ee06a1883d411348de9cb889b2439f8d5bb8fe7252dda0ec1342b208c74d6783e00a982e057234595ba3e66618f58e312c63c9a2b53c197319c72c8480528c1f3b22b7671457e9b013035ebed779192d6d007a7333a5762290dda0badb66dbae3b2e49a0c0f9a5f504ba31bbe9f1fba14dc69c943154da49e2170660311ea156c41f2a027a8fa0f210bafda129a58b306bf53e31286c2ecec107019331b41f14e52bdce00d06fe127cef320ccd063cbdd4a1d3ad036899f02667c5ba9d10b6bd752a9f53e421b93bb9f0f80e10b7fe362f761661fe3c7e2b8b625d6827556825e21f608575f42c5094b3a2ed03e913fd91ed512bcf39a5d9c3dddba17051ac1ce82ddcf610c2937820e7f104f07c7fb7e05ea516aff6d5d24e46fd396c521d9e1110336f7730e7e37aeadc7c93bd7a3ca3b6f190ba0d8588a49c38dc2b62ff4ec31e4edaa29d58bbc50d543d5e1d58fc7308e2f6b7ec203e688b5e59910ceaa51d0248380467789392d41f5fdcfb00947840ff00f79eb7ebe35fedb8adc0dad7dd20bb8f0747f7701e6f789ae3e5053b97f757a71ca7578d8cc715bdf4160751602ae64905f56a120354cc3eff70b49f703d0e764926a27a39cb6981c3890e9d5b0cb95deebda31b28072a611222e141f23a963aabd12ab31448f1cc9fe2861ce107a4dce46daf29257099902577cd1dc782051f6e11ff04e7debf636235be4e242bb29c35ee6907aa1b68b16c9fb1e5b2af65463427ba47b30db86f39e45fbc480b56aa0dd1e42dfc6309e962e7dd45cea5fe90a10ca29e64e588bec89e500236255fb7365df1d946791c0891b6f46dd996ca5d671ba502ebb1bb01ac22537f2c099859056da147894372ed9089044439554609b483a998870ce6f9ae2a4a8e0f2d06cf1765d93db97996692eedf3e328700ccf6f906bd1cf81d759d9272794a21e5a190210a1af8375c39061cbf21331457607c363f15fad135eb809d8cd0d0d2f78a000ee3d0c26bcab428e0cfee27cd34795b0f1208b2168d22fa0fdf66f6021c66812b90051c63e956852c9d6b4ccfd1f6fd5167d9850fa5ba6b97e9351ab226e273b644776e1721fe603921dff31a5763231a49039c3b87c50512dad2598237d23c41b6eaac6bac791f9e4498bfb491180dca9e1fd06f866d89505a59807";
}
