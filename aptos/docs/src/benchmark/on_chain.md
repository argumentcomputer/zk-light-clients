# Benchmark on-chain verification

Our Light Client is able to produce SNARK proofs that can be verified on-chain. This section will cover how to run the
benchmarks for the on-chain verification.

To be able to execute such tests the repository contains a project called `solidity` that is based
off [Foundry](https://github.com/foundry-rs/foundry) which demonstrates the Solidity verification using so-called
fixtures (JSON files) containing the proof data (proof itself, public values and verification key) required for running
the verification for both epoch-change and inclusion programs. These fixtures are generated from a SNARK proof generated
by the proof servers, but currently the fixtures generated are meant for simple testing only.

The contracts used for testing can be found in the [sphinx-contracts](https://github.com/lurk-lab/sphinx-contracts)
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
[⠒] Compiling 29 files with Solc 0.8.26
[⠢] Solc 0.8.26 finished in 1.11s
Compiler run successful!

Ran 4 tests for test/test_lc_proofs.sol:SolidityVerificationTest
[PASS] testFail_FakeProofEpochChange() (gas: 8660281895700906413)
[PASS] testFail_FakeProofInclusion() (gas: 8660281895700906417)
[PASS] testValidEpochChangeProofPlonk() (gas: 318056)
[PASS] testValidInclusionProofPlonk() (gas: 318103)
Suite result: ok. 4 passed; 0 failed; 0 skipped; finished in 12.52ms (15.70ms CPU time)

Ran 1 test suite in 154.07ms (12.52ms CPU time): 4 tests passed, 0 failed, 0 skipped (4 total tests)
```

Currently, the verification of Plonk proof (either epoch-change or inclusion program) costs ~318k gas.

## Fixture generation

If you wish to either run the tests with custom fixtures or regenerate the existing ones, you can do so by running the
`fixture-generator` Rust program. This program will run the end-to-end proving (either epoch-change or inclusion) and
export the fixture file to the relevant place (`solidity/contracts/src/plonk_fixtures`).

To run the `fixture-generator` for the inclusion program, execute the following command:

```bash
RUST_LOG=info RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3" SHARD_SIZE=4194304 SHARD_BATCH_SIZE=0 cargo +nightly-2024-05-31 run --release --features aptos --bin generate-fixture -- --program inclusion
```

> **Tips**
>
> Check that the fixtures have been updated by running `git status`.

> **Note**
>
> You might be encountering issue with updating `sphinx-contracts` Foundry dependency, in this case try manually
> specifying accessing the submodule via SSH like this:
> ```
> git config submodule.aptos/solidity/contracts/lib/sphinx-contracts.url git@github.com:lurk-lab/sphinx-contracts
> ```
