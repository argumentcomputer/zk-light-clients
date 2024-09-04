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
  (defconst PROOF_VERSION_SIZE 8)

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
      (let ((proof-version (take PROOF_VERSION_SIZE proof)))
        (enforce (= proof-version EXPECTED_SPHINX_PROOF_PREFIX_V101_TESTNET) "Proof with incorrect version")
      )

      (enforce (> (length public-values) INCLUSION_PUBLIC_VALUES_MIN_LENGTH_BYTES) "Incorrect public values length")

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
          (verifier-key (at 'verifier-key proof))
          (proof (at 'proof proof))
          )
      (let ((proof-version (take PROOF_VERSION_SIZE proof)))
        (enforce (= proof-version EXPECTED_SPHINX_PROOF_PREFIX_V101_TESTNET) "Proof with incorrect version")
      )

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


;; Valid input data from existing ETH fixtures for the demo:

;; Inclusion
;; signer hash: 0969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c9
;; block header: e0fc910000000000
;; inclusion public values: e0fc9100000000000969ed235cf75d25800ea6845c2584af013c1f9617ad2de87202d7e9b93739c95c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f22002fe30a172d0a479f6add89c63b29dce29b6071b3c7e486b0fb4bc431f88501000000000000002000000000000000290decd9548b62a8ef0d3e6ac11e2d7b95a49e22ecf57fc6044b6f007ca2b2ba010000000000000080
;; inclusion vk: 005835dfcad599fa418a0df2b5ecde903b801f7e0706e9530959119ec75aa9e3
;; inclusion proof: a8558442282a2c1f08965e6c1aa740d2fbab4e3efebf4757c43f81dbe8b57842c4d1ab220d29f9dbd7827d424a3a77576e4ae64b78b421e899f4f8a3fe6acaf5591a89c80968a5431250206bfb3cd878e6e1c2d2592ff03f06f4d59f5ed84355d662b94f22fc6de30f2e62c8d898eb370846b7b6315574b8fb47a5b085891912392b5efc2ed53f5caac501fffb81be5d1c534cf1efb567215bb77a35719405b3efe082ea09a796c40463ec7670721ca4907cd00b697e42d94d9a917c0ff7fabca71f150a1b2d25d1cd3436bc64cece5c3f50c921427ff199a28e4a55db1d64edba56667d15ecfe8c2b547fbb9a66e5ae4953f6a156bd98c8cd9e8f244ba5c5c8b41999461eb18376ce78f5d014fe12bc0cffd02a066027d61d1e94a9be729861190683fd082d815fd418afa525a771bcef89d15070ce651592501093f8548cd1462439cc2dde83a67cf1374b367e8c9785307087583b62aab9cd64c232fd8067f5aac57319ff8fd7f3292b55523e2597a82c229c502d5adc68c373a891513c135f1803882beac4d266ccec91e65b60d50affe56e3532c6d941fc5522788209628e1ce5370619144831e776b184bb42aefc3fd6568abc188c32a9f6e594323257759c981d20d870d52605c358b3085e944b3f2c504217cbdfd3254903d78e29e493d18a12236c1c32e435a8117eb9cbd31c522a8ed82eee9bf94e918429d1006c8abab86911f0701498a084fc6cec020afa800ee896e3648787f583522158bc7be28725142658fd8454205b8bb18f2a05aab4179143dee652de8eac359c2b73a2d5b84f33149d3f58535d83e4e0b44bd7456cf986e0b62c381c25302e38ae3250e6a45cbf24947aa8a291ac2a4d3a74680ddbc344347fa1d527a53e9888e74087ba0fdd7a193c9f2db1ba6952300e48f2cdaa86b35802700cb8a0e383c010f1e0a4e18a490daa87d612d1e3a2fc9940bfe67503dfcddba929392ef507f0832dc10afd393312c6ea2bcf75f4515bb148563fd637b7415fbd369c9988ae09e5a1e0c4f0e7ff06143de7917ecc5b95b97741b2671f940891c95b95c66e85f2d52ff200895c4903a12c3ad099271a6cd269e5fa936644b1b27facdf80c88c103fcdd01a8cc37d1df3b14cfaa32c7ebec1f6e41899414d08bea6a8615cb127a632b0d3751d642702336f5570553e9dc2e83dfe0d85b82b0f473f2d4b054802fe25063defd96e98


;; Committee change
;; signer hash: 5d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f988050
;; block header: e0e58f0000000000
;; committee change public values: e0e58f00000000005d32119aae2ee9f88867d5787af5c4df68884a4bf8fff525ff8c408e8f98805085382a0c8b1b38485a3d816f31ab5b23a0eae94d86c90086cd4e7b6e8c5c46825ebd1cf9ea54ce88af740aad4d7e95e742157209f36867ff5d7d490afa91c6bf
;; committee change vk: 0028418ec600456b3768cd78d1af143a057fc71a3cf522c557c7b473762946ee
;; committee change proof: a8558442247eb547fad43ef8b65324e6ac1157639d86ea0bbc466c081e8bf8cf6093fedc23161295c765e7927ae5237c2c09362b1c4d22df967628cfec41539c1391f63501d9bce165f4b065ecbc1bd423688a85bdd0d2d09f854b581b1e2ce9a7872a6d0a592a7c84485d910d73cddab595d0d627a5b4f7a64a2c29cc572607e8dba84a12c69337290b5ab38d52eb616f4df656164b8bc6b9ce141104d59763cc49f84c13cc5fe566f61f9323ab6bb6e3551d9ceead08f2b6f8ccee1579f11793a07a8123e8fb175d71b9e2a11279e6d12d35118c29c8579c4ab3fc5b2c1d10eb8af5082b2aedc347a737e7cdc9b23014d8d4139336ca89e1af547d0d65d805ad8e62b5094b152e2ca12c235943e7474c64f24fda8710245aa6f02e263e439776bcd00d18938ec4a290ffbc2b4eace3c3597f5a5772f710ed0031064ef356959a60f19b0549d49748e894cc9179ad2d4ebac2feff56fe3f916b82aab16344d467a0048d1d8989d661518ccbcb8887ec2c4c687306dbe38047c45ec0841a25e90c2a4f010cb1fbc7567179f96c90a7132b6bd2967afa025a1126e84a641b9fcf155d2f3806a5f20da38f52f335f70e40e8ee954762abdb7006718cd89469bd518eb5454a1874a1eb4635518521a6ca758866a952eb2f4f22a402b6698b28310a94489ef30deb611239824c5eb341063a4bb7757a8f13005bda0826ae73b67e0898411fd00b9a8a3a37ae5f4c004f2bd8a1cf3bb186b4dde8e6995b7d8c13ea75c4b2bdcf0bf6a5bd2ae792ffe5ce7daa42c9a26fa7acede6e5f84527c3ff7c44ad73e20b165933170a50d9094e4a294a306fc8881cc87fafb8c750541fd1a9def9262661063960f4e8a6b39ada743dde7e176055593d8c32d9f399b6c987f882decedce716841b0aa31a99da6534c4bc25c5e10a7945b953f25d41caf0491bf41548ceca0631047dad0d1d3a291d34b4242f85362acc9049b2ad1f93361826294c837b132682271de90839a10d0264e99d3eb7ece1f90f7641d4c1f5016b0c67260a2b2a0a5d01e8a2fe35a628e76f9cff69edf0e6a69aad40d4333326f9d7543ad208a00b6f4d9d94253fe28722e10135df2ea560fb5d493960c698bf40648dc0907ff418a9e9e6ca0cca866a0b5d0109ed167a4af7be937af488a9c3ff497c726692172bbb317540ca4fa3f0af1e0da05c199acb7f1faa878f602831540cbdb997abb9
