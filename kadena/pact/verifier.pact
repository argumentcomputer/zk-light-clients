(module verifier GOVERNANCE

        ;; TODO: proper governance
        (defcap GOVERNANCE () true)

        ;; Three options for how to represent binary data:
        ;; * Raw strings: "\xFF" -> Downside: no way of turning this into integers
        ;; * Byte lists: [64 127 255] -> Downside: difficult to handle
        ;; * Hex-encoded string: "ff17aa" -> Can use str-to-int and int-to-str to transform each individual chunk
        ;; We chose the latter

        (defschema verifier-schema
                   current-hash:string
                   next-hash:string)

        (deftable verifier-hashes:{verifier-schema})

        (defconst STATE_KEY "hashes")

        ;; constants for public value management -- units in hex-encoded string characters, i.e. 1 byte is 2 characters
        (defconst COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES 208)
        (defconst INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES 236)
        (defconst BLOCK_HEIGHT_BYTE_SIZE 16)
        (defconst COMMITTEE_HASH_BYTE_SIZE 64)
        (defconst EIP1186_PROOF_ADDRESS_BYTE_SIZE 40)
        (defconst EIP1186_PROOF_ADDRESS_HASH_BYTE_SIZE 64)
        (defconst U64_ENCODED_BYTE_SIZE 16)

        ;; These should be fixed to the expected verifier keys for the trusted programs (i.e. hash of ELF file)
        (defconst COMMITTEE_CHANGE_VERIFIER_KEY "TODO: replace me")
        (defconst INCLUSION_VERIFIER_KEY "TODO: replace me")

        ;; TODO: this should trigger the FFI verifier plugin
        (defcap VERIFY_PROOF (proof)
                "TODO"
                true)

        ;; TODO: make these functions internal only
        (defun get-hashes ()
          (read verifier-hashes STATE_KEY))

        ;; TODO: make these functions internal only
        (defun init-hashes (current-hash:string next-hash:string)
          (insert verifier-hashes STATE_KEY { 'current-hash: current-hash, 'next-hash: next-hash }))

        ;; NOTE: to flip endianness of a u64 and turn it into an integer, using util-strings/util-lists:
        ;; (concat (reverse (split-chunks 2 "e0e58f0000000000")))

        (defun committee-change-processing (proof:object)
          ;; First: we verify the proof with the FFI verifier plugin
          ;;(require-capability (VERIFY_PROOF proof))

          ;; Then, we extract the hex-encoded public values and verifier key hash from the proof
          (let ((public-values (at 'public-values proof))
                (verifier-key (at 'verifier-key proof)))
            ;; Check that the public values length match and verifier key matches the expected program
            (enforce (= (length public-values) COMMITTEE_CHANGE_PUBLIC_VALUES_LENGTH_BYTES) "Incorrect public values length")
            ;;(enforce (= verifier-key COMMITTEE_CHANGE_VERIFIER_KEY), "Proof for incorrect program")

            ;; Extract the values out of the public values string
            (let ((block-height (take BLOCK_HEIGHT_BYTE_SIZE public-values))
                  (signer-committee (take COMMITTEE_HASH_BYTE_SIZE (drop BLOCK_HEIGHT_BYTE_SIZE public-values)))
                  (updated-committee (take COMMITTEE_HASH_BYTE_SIZE (drop (+ COMMITTEE_HASH_BYTE_SIZE BLOCK_HEIGHT_BYTE_SIZE) public-values)))
                  (next-committee (take COMMITTEE_HASH_BYTE_SIZE (drop (+ (* COMMITTEE_HASH_BYTE_SIZE 2) BLOCK_HEIGHT_BYTE_SIZE) public-values))))
              ;; for debugging:
              ;;(format "block-height: {}, signer: {}, updated: {}, next: {}" [block-height signer-committee updated-committee next-committee])
              (with-read verifier-hashes STATE_KEY { 'current-hash := current-hash, 'next-hash := next-hash }
                         ;; Check that the signer committee is one of the two stored hashes
                         (enforce (or (= current-hash signer-committee) (= next-hash signer-committee)) "Signer committee must be stored"))
              ;; Update internal verifier state with the new hashes
              (update verifier-hashes STATE_KEY { 'current-hash: updated-committee, 'next-hash: next-committee })
              )
            )
          )
        )

(create-table verifier.verifier-hashes)
