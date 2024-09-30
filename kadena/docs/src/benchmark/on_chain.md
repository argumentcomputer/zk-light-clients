# Benchmark on-chain verification

Our Light Client is able to produce SNARK proofs that can be verified on-chain. This section will cover how to run the
benchmarks for the on-chain verification.

To be able to execute such tests the repository contains a project called `solidity` that is based
off [Foundry](https://github.com/foundry-rs/foundry) which demonstrates the Solidity verification using so-called
fixtures (JSON files) containing the proof data (proof itself, public values and verification key) required for running
the verification for both epoch-change and inclusion programs. These fixtures are generated from a SNARK proof generated
by the proof servers, but currently the fixtures generated are meant for simple testing only.

The contracts used for testing can be found in the [sphinx-contracts](https://github.com/argumentcomputer/sphinx-contracts)
repository which is used as a dependency.

## Requirements

Make sure that you have properly set up the `sphinx-contracts` submodule. If you haven't done so, you can do it by
running the following command:

```bash
git submodule update --init --recursive
```

## Run the tests

To run the tests, navigate to the `solidity/contracts` directory and execute the following command:

```bash
cd solidity/contracts && \
  forge test
```

The output should look like this:

```
% cd solidity/contracts && forge test
[⠊] Compiling...
[⠔] Compiling 30 files with Solc 0.8.26
[⠒] Solc 0.8.26 finished in 1.40s
Compiler run successful!

Ran 8 tests for test/test_lc_proofs.sol:SolidityVerificationTest
[PASS] testFailSmallerConfirmationWorkThreshold1() (gas: 368706)
[PASS] testFailSmallerConfirmationWorkThreshold2() (gas: 359125)
[PASS] testSuccessfulLongestChainVerification() (gas: 414174)
[PASS] testSuccessfulLongestChainVerificationForkCase() (gas: 416590)
[PASS] testSuccessfulSpvVerification() (gas: 432963)
[PASS] testSuccessfulSpvVerificationForkCase() (gas: 435225)
[PASS] testValidLongestChainProofCore() (gas: 2319057)
[PASS] testValidSpvProofCore() (gas: 2319588)
Suite result: ok. 8 passed; 0 failed; 0 skipped; finished in 27.39ms (129.17ms CPU time)

Ran 1 test suite in 87.85ms (27.39ms CPU time): 8 tests passed, 0 failed, 0 skipped (8 total tests)
```

Currently, the verification of a Plonk proof costs ~318k gas.

## Fixture generation

If you wish to either run the tests with custom fixtures or regenerate the existing ones, you can do so by running the
`fixture-generator` Rust program. This program will run the end-to-end proving (either longest chain or spv) and
export the fixture file to the relevant place (`solidity/contracts/src/plonk_fixtures`).

To run the `fixture-generator` for the inclusion program, execute the following command:

```bash
RECONSTRUCT_COMMITMENTS=false SHARD_BATCH_SIZE=0 SHARD_CHUNKING_MULTIPLIER=64 SHARD_SIZE=4194304 RUSTFLAGS="-C target-cpu=native -C opt-level=3 --cfg tokio_unstable" cargo run --release --bin generate-fixture -- --program <longest_chain|spv> --language solidity
```

> **Tips**
>
> Check that the fixtures have been updated by running `git status`.

> **Note**
>
> You might be encountering issue with updating `sphinx-contracts` Foundry dependency, in this case try manually
> specifying accessing the submodule via SSH like this:
> ```
> git config submodule.aptos/solidity/contracts/lib/sphinx-contracts.url git@github.com:argumentcomputer/sphinx-contracts
> ```
