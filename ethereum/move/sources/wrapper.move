module plonk_verifier_addr::wrapper {
    use std::signer;
    use plonk_verifier_addr::plonk_verifier;
    use std::vector;
    use std::vector::{length, slice, push_back, reverse};
    use plonk_verifier_addr::utilities::bytes_to_uint256;
    use std::string::utf8;

    const ERROR_LENGTH_VK: u64 = 4001;
    const ERROR_LENGTH_RAW_PUBLIC_INPUTS: u64 = 4002;
    const ERROR_LENGTH_PROOF: u64 = 4003;
    const ERROR_COMMITTEE_CHANGE: u64 = 4004;
    const ERROR_INCLUSION: u64 = 4005;
    const ERROR_COMMITTEE_CHANGE_UNEXPECTED_PUBLIC_VALUES: u64 = 4006;
    const ERROR_INCLUSION_UNEXPECTED_PUBLIC_VALUES: u64 = 4007;

    const COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES: u64 = 8 + 32 + 32 + 32;
    const INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES: u64 = 32 + 8 + 20 + 32 + 8 + 40 + 8;

    struct Hashes has drop, store, key {
        current_hash: u256,
        next_hash: u256,
    }

    public fun publish(account: &signer, current_hash: u256, next_hash: u256) {
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

    public fun update_current_hash(account: &signer, hash: u256) acquires Hashes {
        // only owner of 'Hashes' resource can update it
        let c = move_from<Hashes>(signer::address_of(account));
        c.current_hash = hash;
        move_to(account, c)
    }

    public fun update_next_hash(account: &signer, hash: u256) acquires Hashes {
        // only owner of 'Hashes' resource can update it
        let c = move_from<Hashes>(signer::address_of(account));
        c.next_hash = hash;
        move_to(account, c)
    }

    public fun delete(account: &signer): (u256, u256) acquires Hashes {
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
        assert!(length(&vkey) == 32, ERROR_LENGTH_VK);
        assert!(length(&proof) % 32 == 0, ERROR_LENGTH_PROOF);

        // convert vkey
        let vkey: u256 = bytes_to_uint256(vkey);

        // convert proof
        let i = 0;
        let n = length(&proof) / 32;
        let proof_in = vector::empty<u256>();
        while (i < n) {
            let chunk = slice(&proof, i * 32, i * 32 + 32);
            push_back(&mut proof_in, bytes_to_uint256(chunk));
            i = i + 1;
        };

        // execute core verification
        plonk_verifier::verify(proof_in, vkey, public_values);

        // post processing
        let block_height = slice(&public_values, 0, 8);
        let signer_sync_committee = bytes_to_uint256(slice(&public_values, 8, 32 + 8));
        let updated_sync_committee = bytes_to_uint256(slice(&public_values, 32 + 8, 32 + 8 + 32));
        let next_sync_committee = bytes_to_uint256(slice(&public_values, 32 + 8 + 32, 32 + 8 + 32 + 32));

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
        assert!(length(&vkey) == 32, ERROR_LENGTH_VK);
        assert!(length(&proof) % 32 == 0, ERROR_LENGTH_PROOF);

        // convert vkey
        let vkey: u256 = bytes_to_uint256(vkey);

        // convert proof
        let i = 0;
        let n = length(&proof) / 32;
        let proof_in = vector::empty<u256>();
        while (i < n) {
            let chunk = slice(&proof, i * 32, i * 32 + 32);
            push_back(&mut proof_in, bytes_to_uint256(chunk));
            i = i + 1;
        };

        // execute core verification
        plonk_verifier::verify(proof_in, vkey, public_values);

        // post processing
        let block_height = slice(&public_values, 0, 8);
        let signer_sync_committee = bytes_to_uint256(slice(&public_values, 8, 32 + 8));
        let eip1186_proof_address = slice(&public_values, 32 + 8, 32 + 8 + 20);
        let eip1186_proof_address_hash = slice(&public_values, 32 + 8 + 20, 32 + 8 + 20 + 32);
        let eip1186_proof_length = slice(&public_values, 32 + 8 + 20 + 32, 32 + 8 + 20 + 32 + 8);
        let zero_key = slice(&public_values, 32 + 8 + 20 + 32 + 8, 32 + 8 + 20 + 32 + 8 + 40);
        let zero_value_length = slice(&public_values, 32 + 8 + 20 + 32 + 8 + 40, 32 + 8 + 20 + 32 + 8 + 40 + 8);
        reverse(&mut zero_value_length);
        let zero_value = slice(&public_values, 32 + 8 + 20 + 32 + 8 + 40 + 8, 32 + 8 + 20 + 32 + 8 + 40 + 8 + (bytes_to_uint256(zero_value_length) as u64));

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
            aptos_std::debug::print(&utf8(b"key[0]:"));
            aptos_std::debug::print(&zero_key);
            aptos_std::debug::print(&utf8(b"value[0]:"));
            aptos_std::debug::print(&zero_value);
        } else {
            assert!(false, ERROR_INCLUSION);
        }
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_storage_flow(a: signer) acquires Hashes {
        publish(&a, InitialHash1, InitialHash2);
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
        publish(&a, InitialHash1, SignerSyncCommitteeHashH29);

        committee_change_event_processing(&a, EpochChangeVk, EpochChangeProof, EpochChangePublicValues);

        let (left, right) = delete(&a);
        // Committee change happened (since SignerSyncCommitteeHashH29 was in storage)
        assert!(left == UpdatedSyncCommitteeHashH30,  1);
        assert!(right == NextSyncCommitteeHashH31 , 2);
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_committee_change_is_allowed_too(a: signer) acquires Hashes {
        publish(&a, SignerSyncCommitteeHashH29, InitialHash2);

        committee_change_event_processing(&a, EpochChangeVk, EpochChangeProof, EpochChangePublicValues);

        let (left, right) = delete(&a);
        // Committee change happened (since SignerSyncCommitteeHashH29 was in storage)
        assert!(left == UpdatedSyncCommitteeHashH30,  1);
        assert!(right == NextSyncCommitteeHashH31 , 2);
    }

    #[test(a = @plonk_verifier_addr)]
    #[expected_failure(abort_code = ERROR_COMMITTEE_CHANGE)]
    public fun test_committee_change_is_not_allowed(a: signer) acquires Hashes {
        publish(&a, InitialHash1, InitialHash2);

        // panics, since SignerSyncCommitteeHashH29 was NOT in storage initially
        committee_change_event_processing(&a, EpochChangeVk, EpochChangeProof, EpochChangePublicValues);
    }


    #[test(a = @plonk_verifier_addr)]
    public fun test_inclusion_is_allowed(a: signer) acquires Hashes {
        publish(&a, ValidSignerSyncCommitteeHashInclusion, InitialHash2);
        // doesn't panic, since SignerSyncCommitteeHashH29 is in storage
        inclusion_event_processing(&a, InclusionVk, InclusionProof, InclusionPublicValues);

        delete(&a);
    }


    #[test(a = @plonk_verifier_addr)]
    public fun test_inclusion_is_allowed_too(a: signer) acquires Hashes {
        publish(&a, InitialHash1, ValidSignerSyncCommitteeHashInclusion);
        // doesn't panic, since SignerSyncCommitteeHashH29 is in storage
        inclusion_event_processing(&a, InclusionVk, InclusionProof, InclusionPublicValues);

        delete(&a);
    }

    #[test(a = @plonk_verifier_addr)]
    #[expected_failure(abort_code = ERROR_INCLUSION)]
    public fun test_inclusion_is_not_allowed(a: signer) acquires Hashes {
        publish(&a, InitialHash1, InitialHash2);
        // panics, since SignerSyncCommitteeHashH29 is NOT in storage
        inclusion_event_processing(&a, InclusionVk, InclusionProof, InclusionPublicValues);
    }

    const InitialHash1: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    const InitialHash2: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    const ValidSignerSyncCommitteeHashInclusion: u256 = 0x0969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c9;
    const SignerSyncCommitteeHashH29: u256 = 0x5d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f988050;
    const UpdatedSyncCommitteeHashH30: u256 = 0x85382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c4682;
    const NextSyncCommitteeHashH31: u256 = 0x5ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf;

    const EpochChangeVk: vector<u8> = x"00bcfcc3dcbdc7f3c1eeb99dce85dd389dfe4896e94494f22740c3f56965ff78";
    const EpochChangePublicValues: vector<u8> = x"e0e58f00000000005d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f98805085382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c46825ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf";
    const EpochChangeProof: vector<u8> = x"1c4d9239aa37ce4e46a51548849ee6f80ebbd5b7297d8ee219c7e243938fe3091b7eb59e14352e7375f9d26affef30bbc37307d50f4f13e6393b94dd926bcad50380a78c1ef216d777784e1fa2a4c0e53ffa09dd5f98e3adb8d613133f0c35c016711f4bd906b35d52bfb95a35a7333a1c166e04d0224cad8d464c73e98e440f0ee507235a17b7a742da7bd8af131eb6fd8ae08df9795c14987b370a916dc3c224903e09963046e687ca6d8f995619a50d6d840acc26c3ba55b005a5bd14db9a303c426cedc49c2da933ccd9f12817262c78db4b0b5c34003752f84b801c11950da266d3568e6765e35998c70d381b7f7c1e5a291795cbba76ba9d4dd99577882a686c3abfb1fde1e1ffb24ddfb248c9cb2ad38fdad6638f69752b5e854336c220db999f2f20766164559a1529d90d5feed42befc81933ae426b637b82d6a84d12677dcca6035905febe868c6d0f0761bb83cb581c1e19e97a412ccf513df53103b97bac07501414b2c388a550961a078ee93f1610324aa78389ce648d6ae5c307351c17e241b7990c44b8f98ad3be8097fd375a9a35812081ef74b455f7e9b217fe1b56f2b9d5d4952827b5e8975fcf9d135391314161acdfeaf14db9d98baf1778e9dadc6074119811041f9feaef0d935c89633570bc49550a7133745628382ed6dcb04b3041942209fc20b034f515400a4b7b8ce6c142ab22878ab4b033ec10492dd7eb8093816038fe5bfef120ae435ec4e2a1f149e1777a9faab436924e19c54b2619f2ac9bf6b1c89a9cfe30f9fe556450a12bf43a9d15d1b0e8dc38ee2b2df1b3d36c496dc42f0151ebddafc7414486d6112a8432f6a534d2dd20f3730c9522c33bb531c518309938898c2223fb697038fc85cf1b9c4369e83280fb3f1efde55d698a32e546f90565588a97f7694bbefd316b92152ddb1e7fb3c4c1872df421106581245876b6aea345633dbf7a727bf91797591f665e31c6e823aff325ad8db2fdc6182255ed4b79da91df21ce25d09291d0806da1f47470afa6e75123aa972bbd5fa473011fea66612c6165755bfd5a762ee32460789d9e402f789f2ee65a0e34a9a80bd906aa3fcb53d6ac6e22a0b16d3e5f4bfcea8f5310d687cb12ccf639a010e2a179274c3535888644ece752730dc63c5f2e5c680259b345650f2aa4e3d097b6e9850302be4ebfb71449a5fe76b69ed28f3276b1432504fbdf";

    const InclusionVk: vector<u8> = x"00a4bfebb1b7e0ec5ba69c8735540a0a56bfdc7dd0816c64a47c932406eff668";
    const InclusionPublicValues: vector<u8> = x"e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba0100000000000000010000000000000080";
    const InclusionProof: vector<u8> = x"18eccca3a8940e062f8e740456d4be747a1be744c28ac06657c7c241ab7abca01ea3636892f2f699b9c263262d8e4f0dba7f6deda3f18acbaf3e8afe067b3a751dca7502ec3819ad0fa821a68406d3a70b24ea21e5e7a9d1ae805877dbbf754c1b780ef900339e13cffcb0534be963b7e25a638ce39e59b9471012882486e9612d2e1db6e89ab9ac9dd1267d1d3d73ff424de5877fe1da09e28612ab1c24b1d32018584fc32f6cdefdbcbb12880e8671dfe2c083a03cd4ee2041b0de187bcd7900ecdf820c4dd6b9a2bb988bb0d83f5b34ded87af2bd39a04bfd8f1375ead222058cd0bbfc7920fa8cff5e348c240065de948d4f7c24246622a0ccd3ce6c8a171575ba7225e8f2b6b8abae637d3ab5e9b53c1c631eea42109f4df319d6c2ada528143a21737681fda1fbaca0427d57dd56cf1b94f1c1cc3f11f6376fc7e83fb312b53334b23acaa17c994257bb3d8831602038d8cedb5c26d97c4743bdbff52922d154019b34addca07bce76347d960a4a1486306124e362516491efe5597fdf146adf9a9a0f5e407968cd1d1a33f0ea0206faa047c5fabc103ce7225dbab1ad219a48d2f1c267fbb30fccf6460238db85041e81caa03f5baafed148bfe6038522e951d42a24dbc6334e675f3bd67a1991d447369c38034156cc1abbfbb926da0416d2d09caaf4f3d11207d2c9e10b385282d4e7b8ba37a1e02d0e8b0a3e5a6313dca979544190a53b1f538acfd04316acf1d6b64e3a55c2ac1946a86b7134450b96db83da150e44e36206bdc44e2241f0daef7aa74f32ca5991d8e0ee6dd0aa158f98848e4b0f6397d46f20722d7945e12b5c1c2fbc8ba7d84b96d34dbb33f92786e166664f7630e819879ee21cbca12c8a24d4141978a874a6bfa5786fafd32fa1234dd2f347e1ad1e3ec97728c78925236a423d53cd43c6ff9129b89893611a50acd847251e80ba44b857d26fc5cc0fa283a7f3801f84dcd603bb57b07e1611272a285e07801ccb72572c63b2c690d898012042836dc7082409374ea314dd2e61f4d955fca27761e4c05c8fc94a281611317105fec1dd6906ba520413b16a25a71b67029038ccc67ce23fa21b0c677df89445e4df99fbf8009aeb74cbeb2e08de0e0de864da06d000ae28c9524c6fd5ac0a55b27f0ce7db0a4f4b6bef1eed1bf3a65b9fd78b60777ea32c00597fa2a6f595c90381d500f667f7af6271d37b";

}
