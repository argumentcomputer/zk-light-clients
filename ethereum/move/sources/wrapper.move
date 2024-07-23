module plonk_verifier_addr::wrapper {
    use std::vector;
    use std::signer;
    #[test_only]
    use std::vector::push_back;

    const ERROR_COMMITTEE_CHANGE: u64 = 4001;
    const ERROR_INCLUSION: u64 = 4002;

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

    public fun committee_change_event_processing(a: &signer, public_values: vector<u256>) acquires Hashes {
        // TODO: add proof verification, e.g.:
        // plonk_verifier::verify(proof, vkey, public_values);

        let _ = *vector::borrow(&public_values, 0); // block height is not actually used in comittee change event post-processing
        let signer_sync_committee = *vector::borrow(&public_values, 1);
        let updated_sync_committee = *vector::borrow(&public_values, 2);
        let next_sync_committee = *vector::borrow(&public_values, 3);

        let curr_hash_stored = get_current_hash_stored(signer::address_of(a));
        let next_hash_stored = get_next_hash_stored(signer::address_of(a));

        if ((signer_sync_committee == curr_hash_stored) || (signer_sync_committee == next_hash_stored)) {
            // allow updating stored values as soon as 'signer_sync_committee' is in storage
            update_current_hash(a, updated_sync_committee);
            update_next_hash(a, next_sync_committee);
        } else {
            assert!(false, ERROR_COMMITTEE_CHANGE);
        }
    }

    public fun inclusion_event_processing(a: &signer, public_values: vector<u256>) acquires Hashes {
        // TODO: add proof verification, e.g.:
        // plonk_verifier::verify(proof, vkey, public_values);

        let _block_height = *vector::borrow(&public_values, 0); // block height is not actually used in inclusion event post-processing
        let signer_sync_committee = *vector::borrow(&public_values, 1);
        let _eip1186_proof_hash = *vector::borrow(&public_values, 2); // eip1186_proof_hash is not actually used in inclusion event post-processing

        let curr_hash_stored = get_current_hash_stored(signer::address_of(a));
        let next_hash_stored = get_next_hash_stored(signer::address_of(a));

        if ((signer_sync_committee == curr_hash_stored) || (signer_sync_committee == next_hash_stored)) {
            // allow funds transfer
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

        let public_values = get_test_public_inputs_committee_change();

        committee_change_event_processing(&a, public_values);

        let (left, right) = delete(&a);
        // Committee change happened (since SignerSyncCommitteeHashH29 was in storage)
        assert!(left == UpdatedSyncCommitteeHashH30,  1);
        assert!(right == NextSyncCommitteeHashH31 , 2);
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_committee_change_is_allowed_too(a: signer) acquires Hashes {
        publish(&a, SignerSyncCommitteeHashH29, InitialHash2);

        let public_values = get_test_public_inputs_committee_change();

        committee_change_event_processing(&a, public_values);

        let (left, right) = delete(&a);
        // Committee change happened (since SignerSyncCommitteeHashH29 was in storage)
        assert!(left == UpdatedSyncCommitteeHashH30,  1);
        assert!(right == NextSyncCommitteeHashH31 , 2);
    }

    #[test(a = @plonk_verifier_addr)]
    #[expected_failure(abort_code = ERROR_COMMITTEE_CHANGE)]
    public fun test_committee_change_is_not_allowed(a: signer) acquires Hashes {
        publish(&a, InitialHash1, InitialHash2);

        let public_values = get_test_public_inputs_committee_change();

        // panics, since SignerSyncCommitteeHashH29 was NOT in storage initially
        committee_change_event_processing(&a, public_values);
    }


    #[test(a = @plonk_verifier_addr)]
    public fun test_inclusion_is_allowed(a: signer) acquires Hashes {
        publish(&a, SignerSyncCommitteeHashH29, InitialHash2);
        let public_values = get_test_public_inputs_inclusion();
        // doesn't panic, since SignerSyncCommitteeHashH29 is in storage
        inclusion_event_processing(&a, public_values);
    }

    #[test(a = @plonk_verifier_addr)]
    public fun test_inclusion_is_allowed_too(a: signer) acquires Hashes {
        publish(&a, InitialHash1, SignerSyncCommitteeHashH29);
        let public_values = get_test_public_inputs_inclusion();
        // doesn't panic, since SignerSyncCommitteeHashH29 is in storage
        inclusion_event_processing(&a, public_values);
    }

    #[test(a = @plonk_verifier_addr)]
    #[expected_failure(abort_code = ERROR_INCLUSION)]
    public fun test_inclusion_is_not_allowed(a: signer) acquires Hashes {
        publish(&a, InitialHash1, InitialHash2);
        let public_values = get_test_public_inputs_inclusion();
        // panics, since SignerSyncCommitteeHashH29 is NOT in storage
        inclusion_event_processing(&a, public_values);
    }


    const InitialHash1: u256 = 0x1111111111111111111111111111111111111111111111111111111111111111;
    const InitialHash2: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    const BlockHeight: u256 = 0x000000000000000000000000000000000000000000000000000000000000000a;
    const SignerSyncCommitteeHashH29: u256 = 0x5d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f988050;
    const UpdatedSyncCommitteeHashH30: u256 = 0x85382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c4682;
    const NextSyncCommitteeHashH31: u256 = 0x5ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf;

    #[test_only]
    public fun get_test_public_inputs_committee_change(): vector<u256> {
        let public_inputs = vector::empty<u256>();
        push_back(&mut public_inputs, BlockHeight);
        push_back(&mut public_inputs, SignerSyncCommitteeHashH29);
        push_back(&mut public_inputs, UpdatedSyncCommitteeHashH30);
        push_back(&mut public_inputs, NextSyncCommitteeHashH31);
        public_inputs
    }

    const Eip1186ProofHash: u256 = 0x8ce1cdb7b09e757a1f7dbd6278a380a7d5e646a94b90b394c9efdd283a1420df;

    #[test_only]
    public fun get_test_public_inputs_inclusion(): vector<u256> {
        let public_inputs = vector::empty<u256>();
        push_back(&mut public_inputs, BlockHeight);
        push_back(&mut public_inputs, SignerSyncCommitteeHashH29);
        push_back(&mut public_inputs, Eip1186ProofHash);
        public_inputs
    }
}
