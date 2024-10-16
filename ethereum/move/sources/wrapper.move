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
    const EpochChangeVk: vector<u8> = x"00c55464e91190f7548e4355c11cc43c1187f73cb1547a37aba0e6a1760a11d0";
    const EpochChangePublicValues: vector<u8> = x"e0e58f00000000005d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f98805085382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c46825ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf";
    const EpochChangeProof: vector<u8> = x"7f8918df0301eab6bcabf49c2710a694a0cd215be9254bd774d54b6ec8fa8328525e5f5500f376ef87a1f736abcad7df13173e2f16f40a4fc382b4d847b5139cb85314792ce8edd0b1f61b1fff0f462261e452c03e2ae8de4c32a5b236c74847fcedef540c2cb2dc48b8598c6ec7f4a9a859cb2eb04a192771b57cfa4a1c470480d1faf012bc6bc7f4fd470fef2c41d7d831be5c3929bd0a2cc990d0498d0202624d2f0310f67be711829525766ba5bf26501ea299c6237c199066b95fd7239c538561c51ccb2ec4b2ab47d23333a891f917f3b1eae3b71dd87b9e9476498a1a5d41aab32d4b07a99c9ce3a42eb155ec0d419c3785f3393b4063e7888c59223ebeed84940f7aaa1d96b7415ff23b93af83934b460ebf651f9670560c2f9a7880daefce591526584e6950fcf7308923cb8217ab6442c46899bf6c87183283718be871213411ab2a8e4ac7b19552fb0ebe62970f54a426abcddd7d86e4d2768ce9eda3c942243891b5faa8cf8f38a075bac4f757b83549009bdc4434ac293ea7b3f4361aa90ad2d9830cb5e782efb157ee68ee0cac6cca3b938d2304da7b5aef0baff459562c8b23d4a79499b0a26a3304042212e14834774e891a1587be696838dadcddc6211daee2da80ca803b6911c9a8fb8b127400df3ee50b04a5c3a232784ae04aae040258000e77f9b6658b1c23724a881635c4b4b4d149b01820940d1eff9690ea11498998f965dede6ad1e169b0f1bcdf2aa2c05f98df5bf5270454a37d8621db1c61ae47bfef2e39732498d36577072434d8a8fecd20b997d0625788450ad3ae0e3737ceaa1ccd33f234b7eb184692f49be0779481fffef3dfc89293c85cfd630289c5b6fa639dc45b1eb45908caa996553ae40af0d17f6040306edc6cd3dc7312e300eb5498eea2ee12d7fb4c3571d3cce970335e8960479b5b542273a664f62c069a37d137340deea79f6ac988f5f27b34f7e2fc2bd1b632107aa4a14d2f5b0339b2fbb492fb569cc47b6244df5a4c50df506e3efce434f8fdaf4bd8d3207928b1b0bc5ab666e34eac14dd8cf061401487550c0f2afd285595c4e02c518db616a6a8f10e9210df423c9e0cbdeaf0155d1d001326592dd26e920d2e0f1479ca0c9b74114622d19aee57ed2e56a2c57a099105843c8fce2ae43d19f80c22494911089ea61cab1a4141b265013cf0a0688f311f2c235e5213dac7fb969a381ef4";

    // From inclusion fixture
    const ValidSignerSyncCommitteeHashInclusion: u256 = 0x0969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c9;
    const InclusionVk: vector<u8> = x"00d6b0922b33f4a88cac7a71b76e025fa0dfb9b3a2e74e009bd511db5688bd3d";
    const InclusionPublicValues: vector<u8> = x"e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba010000000000000080";
    const InclusionProof: vector<u8> = x"7f8918df1f7ecf988279a5903ac9186fb441f8abf319dbc712ba375bd1350f6dd736c0ad26f4cdacce1b7ce64c04dc674cf60bb9eda8326fb54e944a6b98dac5a12d521c04156edcd07860aa0c7b240459141c19a368051977db8d513308f66127854b15167aa4584770ee7eb2f766d96517f3b141ecfe09bb5510bf707561bc47b8ecf41ac1d57ae6e6229d283c3bdf95e25f6b372f378b2ab1f948692d0411043993420f1a18502cb0df01d70f294a82fb6a884520c2e2ebe1f51161f0d5b46a6ab6a22d68d5a26eae9c2c3a3927420ebe5a5b9529860a3cd77c58cabb984b829203c806c0ae08e03d61ead010b2158da38b2313b9f52d257b29f3fd3cce9181439140071f3d100c2eacb14bf3d5929e0fa3622f2c0ece50e3c9095fd0d666e0ebab782bece4c9dd1146e717f38c16f323b656720205c79bd38ae8d6e0f0d00c042efa07cce994d9a484ee91c09f215c06fa149857fff143dcaeda634f770552e5a4c81975107909f7fe9a094f1d6d2e6dd1e9120874c82206d72b851c78d913121ef4006aeaad4699c3821523f6abfb7a8ff583307dec352b55b3d8d6181925002ff928c495ddf12f534ba4cb7e8f1240a7de18ec9b9ceff3131857176026bcb49b06109a66a659d4303674a21a364110de8561ebef7905982c4c791c0b1dac8234dc248eaacdc575b851a09f27b6f8753378a2545c90c113349476b0fb9b3677196928866f5d9ca003194f6ef3560e5a65c56050f899252b0b56cc43b074b35b07f80d8fcaaaecd2e7b3488671c9ce056335ac03cf1584308115f23594c9aee05c3b03553c766c492ed69b3bd874b1f2ece4fe79926cdbe69c1d07536c5aea7a081603cbfae18394e5ddc62be42f1d39c1abaade0bc16540b2ef07fb7bb5a36a417a12810f6188da9dab867f6f3795d252dc7ff240c889775f2b807aa121961b038a28bf1cbf5e98cdba898bc588e60d8639f5ab36e6bdab91287d1af0901cf611811782bc1e8d5fe824d1fc1075957de324ab9c84b11a9835630d63e9b10f0ce46a224be3538237a5d9725bef0ebc17ad2df709e150a1a40ce7de3bc980282d74071664e1222b21cba25edb7f70f3c5be309f702dbaa6fc2595c5141fae3dbd3d2f0181e63e6be01cf1912ae550a42229f16cc7b61784f45f47bddc991c13b4153d0562e4fc958aa71586d68cbcf6cfc2889b3fcd25854ff02b5446111d2f0624e4";
}
