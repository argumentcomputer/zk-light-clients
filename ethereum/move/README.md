### MOVE verifier

This directory includes Move smart contract for running the verification of Sphinx proofs on Aptos blockchain.

In order to install Aptos CLI, follow [this](https://aptos.dev/en/build/cli) instructions. To run verifier's tests:

```
cd ethereum/move
aptos move test
```

This module is configured using setup from [this](https://aptos.dev/en/build/guides/build-e2e-dapp/1-create-smart-contract) tutorial.

It is also possible to run verification over custom JSON fixtures via Move scripting mechanism. In this settings, proof, public inputs and
verification key are passed via arguments to Move script. Note, that fixture should have Aptos-specific format (see `/move/sources/fixtures` for
examples).

To run Move script that executes verification code using JSON fixture (running locally, simulating real transaction):

```
aptos account fund-with-faucet --account 0x4207422239492c11a6499620c869fe2248c7fe52c05ca1c443bffe8a8878d32 --profile devnet
aptos move compile
aptos move publish --profile devnet
aptos move run-script --compiled-script-path build/plonk-verifier/bytecode_scripts/run_verification.mv --json-file sources/fixtures/fixture_1.json --profile devnet --local
```

You should see tentatively following result if verification passed:

```
{
  "Result": {
    "transaction_hash": "0x62f976db6ba0eaa1951d3ec70d4e7afa9c3189856f54bc3f029e86dc6e6f0330",
    "gas_used": 786,
    "gas_unit_price": 100,
    "sender": "4207422239492c11a6499620c869fe2248c7fe52c05ca1c443bffe8a8878d32d",
    "success": true,
    "version": 26230959,
    "vm_status": "status EXECUTED of type Execution"
  }
}
```

It is known that verification doesn't work with testnet due to serialisation issue of Bn254 field element. This might be fixed with eventual testnet upgrades on Aptos side.
