### MOVE verifier

This directory includes Move smart contract for running the verification of Sphinx proofs on Aptos blockchain.

In order to install Aptos CLI, follow [this](https://aptos.dev/en/build/cli) instructions. To run verifier's tests:

```
cd ethereum/move
aptos move compile --named-addresses plonk_verifier_addr=testnet
aptos move test --named-addresses plonk_verifier_addr=testnet
```

This module is configured using setup from [this](https://aptos.dev/en/build/guides/build-e2e-dapp/1-create-smart-contract) tutorial.

It is also possible to run verification over custom JSON fixtures via Move scripting mechanism. In this settings, proof, public inputs and
verification key are passed via arguments to Move script. Note, that fixture should have Aptos-specific format (see `/move/sources/fixtures` for
examples).

To run Move script that executes verification code using JSON fixture (running on Aptos `testnet`):

```
aptos move compile --named-addresses plonk_verifier_addr=testnet
aptos move run-script --compiled-script-path build/plonk-verifier/bytecode_scripts/run_verification.mv --json-file sources/fixtures/epoch_change_fixture.json --profile testnet --assume-yes
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
It is possible to run Move verification flow locally. This requires running Aptos node locally using Docker (see [this](https://aptos.dev/en/build/cli/running-a-local-network) tutorial for more details).

### Updating Wrapper contract

When Sphinx version is updated it is usually required to update and publish new correspondent version of
the [plonk-core](https://github.com/argumentcomputer/sphinx-contracts/tree/main/move) dependency. Follow the [README](https://github.com/argumentcomputer/sphinx-contracts?tab=readme-ov-file#smart-contracts-for-sphinx)
from the `sphinx-contracts` repository (if this is not done yet). Additionally, some updates are required in `move/sources/wrapper.move` source file,
specifically new hardcoded values of the fixtures are required. Those values can be obtained in a convenient form while
running [fixture-generator](https://github.com/argumentcomputer/zk-light-clients/tree/dev/fixture-generator) program, while
replacing JSON fixtures in `move/sources/fixtures` path.
