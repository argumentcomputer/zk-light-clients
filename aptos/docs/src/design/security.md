# Security considerations

## Sphinx

The [Sphinx](https://github.com/argumentcomputer/sphinx) prover is a fork of [SP1](https://github.com/succinctlabs/sp1)
and as such inherits a lot from its security design. The current release of Sphinx (`v1.0.0`) has backported all the
upstream security fixes as of SP1 `v1.0.5-testnet`. We will continue to update Sphinx with backports of upstream
security fixes and subsequent updates to both Sphinx and the Light Client making them available as hotfixes.

In terms of Sphinx-specific changes that require special attention, here is a non-exhaustive list of Sphinx
AIR chips used for pre-compiles that are either not present in upstream SP1, or have had non-trivial changes:
- `FieldAddChip`, `FieldSubChip`, `FieldMulChip`: Chips for BLS12-381 Fp acceleration.
- `QuadFieldAddChip`, `QuadFieldSubChip`, `QuadFieldMulChip`: Chips for BLS12-381 Fp2 acceleration.
- `Bls12381G1DecompressChip`: Chip for decompressing BLS12-381 compressed G1 points.
- `Secp256k1DecompressChip`: Chip for decompressing K256 compressed points.

There are some SP1 chips and pre-compiles that are not present in Sphinx, such as `Uint256MulChip`.
