(module verifier GOVERNANCE
  ;; TODO: proper governance
  (defcap GOVERNANCE () true)

  ;; Three options for how to represent binary data:
  ;; * Raw strings: "\xFF" -> Downside: no way of turning this into integers
  ;; * Byte lists: [64 127 255] -> Downside: difficult to handle
  ;; * Hex-encoded string: "ff17aa" -> Can use str-to-int and int-to-str to transform each individual chunk
  ;; We chose the latter

  (defschema state-schema
              current-hash:string
              next-hash:string
  )
  (deftable state:{state-schema})

  (defconst STATE_KEY "hashes")

  ;; TODO: this should trigger the FFI verifier plugin
  (defcap VERIFY_PROOF (proof)
          "TODO"
          true)

  ;; TODO: make these functions internal only
  (defun read-state:object ()
    (read state STATE_KEY))

  (defun write-state(current-hash:string next-hash:string)
    (update state STATE_KEY { 'current-hash: current-hash, 'next-hash: next-hash })
  )

  (defun init-state()
    (insert state STATE_KEY { 'current-hash: "", 'next-hash: "" })
  )

  ;; constants for public value management of committee change -- units in hex-encoded string characters, i.e. 1 byte is 2 characters
  (defconst COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH 208)
  (defconst INCLUSION_PUBLIC_VALUES_MIN_LENGTH 236)
  (defconst BLOCK_HEIGHT_LENGTH 16)
  (defconst COMMITTEE_HASH_LENGTH 64)
  (defconst EIP1186_PROOF_ADDRESS_LENGTH 40)
  (defconst EIP1186_PROOF_ADDRESS_HASH_LENGTH 64)
  (defconst U64_ENCODED_LENGTH 16)
  (defconst PROOF_VERSION_LENGTH 8)

  ;; These should be fixed to the expected verifier keys for the trusted programs (i.e. hash of ELF file)
  (defconst EXPECTED_COMMITTEE_CHANGE_VERIFIER_KEY "0028418ec600456b3768cd78d1af143a057fc71a3cf522c557c7b473762946ee")
  (defconst EXPECTED_INCLUSION_VERIFIER_KEY "005835dfcad599fa418a0df2b5ecde903b801f7e0706e9530959119ec75aa9e3")
  (defconst EXPECTED_SPHINX_PROOF_PREFIX_V101_TESTNET "a8558442")

  (defun inclusion-event-processing (proof:object)
    ;; First: we verify the Sphinx proof with the FFI verifier plugin
    ;;(require-capability (VERIFY_PROOF proof))

    (let ((public-values (at 'public-values proof))
          (verifier-key (at 'verifier-key proof))
          (proof (at 'proof proof))
          )
      (let ((proof-version (take PROOF_VERSION_LENGTH proof)))
        (enforce (= proof-version EXPECTED_SPHINX_PROOF_PREFIX_V101_TESTNET) "Proof with incorrect version")
      )

      (enforce (> (length public-values) INCLUSION_PUBLIC_VALUES_MIN_LENGTH) "Incorrect public values length")

      (enforce (= verifier-key EXPECTED_INCLUSION_VERIFIER_KEY) "Proof for incorrect program")

      (let ((block-height (take BLOCK_HEIGHT_LENGTH public-values))
        (signer-committee (take COMMITTEE_HASH_LENGTH (drop BLOCK_HEIGHT_LENGTH public-values)))
        (eip1186_proof_address (take EIP1186_PROOF_ADDRESS_LENGTH (drop (+ COMMITTEE_HASH_LENGTH BLOCK_HEIGHT_LENGTH) public-values)))
        (eip1186_proof_address_hash (take EIP1186_PROOF_ADDRESS_LENGTH (drop (+ (+ COMMITTEE_HASH_LENGTH BLOCK_HEIGHT_LENGTH) EIP1186_PROOF_ADDRESS_LENGTH) public-values)))
        )
        (with-read state STATE_KEY { 'current-hash := current-hash, 'next-hash := next-hash }
          ;; Check that the signer committee is one of the two stored hashes
          (enforce (or (= current-hash signer-committee) (= next-hash signer-committee)) "Unexpected signer committee (not in storage)"))

        ;; Finalise successful processing of inclusion event
        (format "Inclusion event has been processed successfully (funds transfer is allowed), for a block-height: {}, eip1186_proof_address: {}, eip1186_proof_address_hash: {}" [block-height, eip1186_proof_address, eip1186_proof_address_hash])
      )
    )
  )

  (defun committee-change-event-processing (proof:object)
    ;; First: we verify the Sphinx proof with the FFI verifier plugin
    ;;(require-capability (VERIFY_PROOF proof))

    ;; Then, we extract the hex-encoded public values and verifier key hash from the proof
    (let ((public-values (at 'public-values proof))
          (verifier-key (at 'verifier-key proof))
          (proof (at 'proof proof))
          )
      (let ((proof-version (take PROOF_VERSION_LENGTH proof)))
        (enforce (= proof-version EXPECTED_SPHINX_PROOF_PREFIX_V101_TESTNET) "Proof with incorrect version")
      )

      (enforce (= (length public-values) COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH) "Incorrect public values length")

      (enforce (= verifier-key EXPECTED_COMMITTEE_CHANGE_VERIFIER_KEY) "Proof for incorrect program")

      ;; Extract the values out of the public values string
      (let ((block-height (take BLOCK_HEIGHT_LENGTH public-values))
        (signer-committee (take COMMITTEE_HASH_LENGTH (drop BLOCK_HEIGHT_LENGTH public-values)))
        (updated-committee (take COMMITTEE_HASH_LENGTH (drop (+ COMMITTEE_HASH_LENGTH BLOCK_HEIGHT_LENGTH) public-values)))
        (next-committee (take COMMITTEE_HASH_LENGTH (drop (+ (* COMMITTEE_HASH_LENGTH 2) BLOCK_HEIGHT_LENGTH) public-values))))

        (with-read state STATE_KEY { 'current-hash := current-hash, 'next-hash := next-hash }
          ;; Check that the signer committee is one of the two stored hashes
          (enforce (or (= current-hash signer-committee) (= next-hash signer-committee)) "Unexpected signer committee (not in storage)"))

        ;; Update internal verifier state with the new hashes
        (update state STATE_KEY { 'current-hash: updated-committee, 'next-hash: next-committee })

        ;; Finalise successful processing of committee change event
        (format "Committee change event has been processed successfully, for a block-height: {}" [block-height])
      )
    )
  )
)

(create-table verifier.state)
