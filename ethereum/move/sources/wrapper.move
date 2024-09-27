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

    const EpochChangeVk: vector<u8> = x"00bb9c681c4466b62efe6f5198bd1e5453b2500ed947810581ab37f2580aa3b3";
    const EpochChangePublicValues: vector<u8> = x"e0e58f00000000005d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f98805085382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c46825ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf";
    const EpochChangeProof: vector<u8> = x"a85584420cd57f98d0674405ad491ffa65d06aeb77212d72d62c5facc6cf57b618268fd8303165cebe8c85d03d7d359458c112e73acfb107c0499db598a748345271ce5b1e8a91c291a639bc8c8c2574bc4b0447554f1cfc1daf0697424e5dfc5f21c8a727d3f14a99d5d031e9e63bc79def7af0729f5607690fc1f33eb13b013d8169b4117fcb772971e207a4fb1cc079af410dab30850c7dbd096c7b474642c7d3d780173f7dbd23e6a0a0402eb0415bfc3f64f9d90eeb45c7381dbb7f8de06b3c68b92dfeecd6cb098ec40f92d947e66928f1cc21e3fe426c3035ffa8dc041d5f1d130253c1616afa7e3ac1100296d1b7e02ff9cb22d4b02d534026eebe79991bec212a7077be94366d313871a31722f491f2955736b97e57979719ba3817049b06861f799f5fd46bed9e6008356120928211c3112a3d6ad32b3689af4d13e80d6ca0198fdca28c2b521e6e37dadb2c630df1ae727b1b19b690e5b99325936bb59bf104f2e5309f6ca2b8727cee7f3ef19576441cce8b42f839a15b3a3316720068a22216cef664a28960dfc45b0a85ed7b79e4aa678e38518224996f765742c169dc17236d46bdb41040908a80698ce9209461f1856dd9e57f5cc2725e3c959ee65b11934e49b1265599d7c0c04a18b68add3b6b3d1601f22c89115cfb6f6fbb403f3035d1cbd896b352292fdf1d6d8020dfe1be76a8b14f4d681dc9b763a6e22aae05267b9f933fa39cbe36667aa9bcefbe0708fc129450d9bef3a4d45fb3a336a609c1b093745fbf870e4aad3ec234ebf4b0cf1238882e3dd0e7fa474f7f10f73f144e4f145a4a88dcb9a184fec77d3695b18a0eb2f556b5e520e736df0f9e01040dbaf528f9fd147fb238e4ec5c4d20381502bdfbc6bfc5de019988b5f4e77ca5200f180077271f1cbec6c6e0971470f6688e480d83c40c728b36e85e0c99b9ea22a893392c90edd356e6318ec8864b990a048cd107fd4e3b201a59921e4861f81d6f62c0e7c8245dba477f2494655fa215e47d8d01a22e35c4750b13104e547f19b1a26591015e9f1dc6db1ab1b60cf7e0eb54b56d351d5832d495bbdc41481c00d3330e0b302e49575282b792bf89ec39946c84d3a93f24cb35501433ce0b5208d7312934466a24a65d4d35d38aca861e835b139de86ba4283367783f9f99dc260c2def5fcb2d7e3423b6fe0cc4726eda51a0144e74f154f2c036a968a87685";

    const InclusionVk: vector<u8> = x"00ac8f803153fab4cd7291beb0eac498f4c7949f74e7786bd69a0578bc325927";
    const InclusionPublicValues: vector<u8> = x"e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba010000000000000080";
    const InclusionProof: vector<u8> = x"a85584420325031b628d531025b0a9ed7a846346c5d0b28ca9903a48ddd8ae739c58f0dc21ef49a01ebc2ef95e1f3989f72e0832965a3b5a908fa5050c74d9162a2f605b13a0d682d5d301ce6e44c44f40025daeded008acc8fcc5178c611ec2b6fdfbb12496f32cd1f99fd80f28cb46ddf7909603b6dd223db93a9378bce7892b3afa171493a69320d2f383c4e505b48d9baac4e1824f03147ac6dd61bffc9154f3d8361d176a85fbe837e1c06cc3ac383b14292440a038663381b8421b853fa171012905ee8ef1eb7cd86afb19b9e4c5911f285965935565cacdc41880b63fb49290b028cd994696aeecedeeca036957bbb0fa3d5f0369774191b73b3078fb36cf348f0e4b3781a083576bbe5ca35644f4a0be66c445b798791423c74075584ad14abd2a1c80fdf84060b407ad6b2547b20bcfcdd5d66a6dff8a91f15785b8b76dff8b10d4da4463ce69cb27070ad711e7251179333474867518d332c10f9a92b37797002ba50aad3d2407f3abebd3c20096ad104f74ddb8bd1f93a7da0381cb91eb9515efa3ef61ebb693501f125966142b116ed314c377c71ddb44967c61ddd1efe21eceb027b6c9b0ca22fc2ea5966a81f9492788a1588c1f6293fcf0abe22c60482d1fe48f09c1381c4e6de67655f38dee93440ae12ae715eda424eb0976aad614288471895e4d73791f2aaa18756177583f963e711ae58c281cc664a84ec09508200025017b717d6a477f613757115b1b5588c7860a54c1ded466aa34d15727b70a4fbabdd03f3ceacec53c104fb141ac4de3c3c8cb012b90f27766fc18fa83e42e685f270199861d080c06e64ddcf0cd2f320d68a4aa8962bc52836ec61efba1183b52115b482af21e79a2fd813ffb60319a0525ff47ec5b80fa2b8116a606b319992cf0e85ef4fee9a7c242ef040583d7265b5b344df5a2032729529ca2738820589dc9b1d5228e840825c7818c187845a3ce9c39395848dcf544e997d9bfe51fe28ee664cf36f843628e87ac413386c0735a4f4fe6410ed4bd0533902890db161d1b45c98162b2a0fdfe30fc2cffb197cd0fbd27fcfdab4a0d710f3fd3eefd195aff571eead04df178ad290b9e25f856fdae12bb7b412ac6a79909e3dee17a08e2f61eec9ffa72cb508122c2c469ad1a1e0645b28a2456910da5e0a540e6c0252b6b23efea0055f623723a9f741f15309e7d9698a03a1daa4e87801daa284f";
}
