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
  (defconst COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES 208)
  (defconst INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES 236)
  (defconst BLOCK_HEIGHT_BYTE_SIZE 16)
  (defconst COMMITTEE_HASH_BYTE_SIZE 64)
  (defconst EIP1186_PROOF_ADDRESS_BYTE_SIZE 40)
  (defconst EIP1186_PROOF_ADDRESS_HASH_BYTE_SIZE 64)
  (defconst U64_ENCODED_BYTE_SIZE 16)

  ;; These should be fixed to the expected verifier keys for the trusted programs (i.e. hash of ELF file)
  (defconst EXPECTED_COMMITTEE_CHANGE_VERIFIER_KEY "0028418ec600456b3768cd78d1af143a057fc71a3cf522c557c7b473762946ee")
  (defconst EXPECTED_INCLUSION_VERIFIER_KEY "005835dfcad599fa418a0df2b5ecde903b801f7e0706e9530959119ec75aa9e3")

  (defun inclusion-event-processing (proof:object)
    ;; First: we verify the Sphinx proof with the FFI verifier plugin
    ;;(require-capability (VERIFY_PROOF proof))

    (let ((public-values (at 'public-values proof))
          (verifier-key (at 'verifier-key proof)))

      (enforce (> (length public-values) INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES) "Incorrect public values length")

      ;; Check that the public values length match and verifier key matches the expected program
      (enforce (= verifier-key EXPECTED_INCLUSION_VERIFIER_KEY) "Proof for incorrect program")

      (let ((block-height (take BLOCK_HEIGHT_BYTE_SIZE public-values))
        (signer-committee (take COMMITTEE_HASH_BYTE_SIZE (drop BLOCK_HEIGHT_BYTE_SIZE public-values)))
        (eip1186_proof_address (take EIP1186_PROOF_ADDRESS_BYTE_SIZE (drop (+ COMMITTEE_HASH_BYTE_SIZE BLOCK_HEIGHT_BYTE_SIZE) public-values)))
        (eip1186_proof_address_hash (take EIP1186_PROOF_ADDRESS_BYTE_SIZE (drop (+ (+ COMMITTEE_HASH_BYTE_SIZE BLOCK_HEIGHT_BYTE_SIZE) EIP1186_PROOF_ADDRESS_BYTE_SIZE) public-values)))
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
          (verifier-key (at 'verifier-key proof)))

      ;; Check that the public values length match and verifier key matches the expected program
      (enforce (= (length public-values) COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES) "Incorrect public values length")
      (enforce (= verifier-key EXPECTED_COMMITTEE_CHANGE_VERIFIER_KEY) "Proof for incorrect program")

      ;; Extract the values out of the public values string
      (let ((block-height (take BLOCK_HEIGHT_BYTE_SIZE public-values))
        (signer-committee (take COMMITTEE_HASH_BYTE_SIZE (drop BLOCK_HEIGHT_BYTE_SIZE public-values)))
        (updated-committee (take COMMITTEE_HASH_BYTE_SIZE (drop (+ COMMITTEE_HASH_BYTE_SIZE BLOCK_HEIGHT_BYTE_SIZE) public-values)))
        (next-committee (take COMMITTEE_HASH_BYTE_SIZE (drop (+ (* COMMITTEE_HASH_BYTE_SIZE 2) BLOCK_HEIGHT_BYTE_SIZE) public-values))))

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


;; Valid input data for the demo:

;; Committee change
;; hash: 5d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f988050
;; block header: e0e58f0000000000
;; epoch change public values: e0e58f00000000005d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f98805085382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c46825ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf
;; epoch change vk: 0028418ec600456b3768cd78d1af143a057fc71a3cf522c557c7b473762946ee

;; Inclusion
;; hash: 0969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c9
;; block header: e0fc910000000000
;; inclusion public values: e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba010000000000000080
;; inclusion vk: 005835dfcad599fa418a0df2b5ecde903b801f7e0706e9530959119ec75aa9e3
