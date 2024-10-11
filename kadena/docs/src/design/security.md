# Security considerations

## Sphinx

The [Sphinx](https://github.com/argumentcomputer/sphinx) prover is a fork of [SP1](https://github.com/succinctlabs/sp1)
and as such inherits a lot from its security design. The current release of Sphinx (`dev`) has backported all the
upstream security fixes as of SP1 `v1.0.8-testnet`. We will continue to update Sphinx with backports of upstream
security fixes and subsequent updates to both Sphinx and the Light Client, making them available as hotfixes.

In terms of Sphinx-specific changes that require special attention, here is a non-exhaustive list of Sphinx
AIR chips used for precompiles that are either not present in upstream SP1, or have had non-trivial changes:

- `Blake2sRoundChip`: Chip for the Blake2s hash function compression, as specified in [RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693).
- `Sha512CompressChip`, `Sha512ExtendChip`: Chips for the SHA-512 hash function compression.

Notably, the Kadena light client does not use BLS12-381 related precompiles, such as field operations (`FieldAddChip`, `FieldSubChip`, `FieldMulChip`) or G1 decompression (`Bls12381G1DecompressChip`), neither does it use `Secp256k1DecompressChip`, a chip for decompressing K256 compressed points. Therefore, the light client’s proof does not depend on the correctness of these precompiles. 

There are also some SP1 chips and precompiles that are not present in Sphinx, such as `Uint256MulChip`.
