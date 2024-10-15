// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Wrapper, SphinxProofFixture} from "../src/Wrapper.sol";
import {SphinxVerifier} from "sphinx-contracts/solidity/src/SphinxVerifier.sol";

contract SolidityVerificationTest is Test {
    using stdJson for string;

    // Values, taken from public values of the fixture: src/plonk_fixtures/epoch_change_fixture.json
    uint256 private constant TestValidSignerHash = 0x205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ec;
    uint256 private constant TestUpdatedSignerHash = 0xc071f215064bfe6f1c24295135199ce6f6dec2974115fad50989e666915453ad;

    Wrapper wrapper;

    function setUp() public {
        bytes32 signer_hash = bytes32(TestValidSignerHash);
        wrapper = new Wrapper(signer_hash);
    }

    function loadPlonkInclusionFixture() public view returns (SphinxProofFixture memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/inclusion_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixture));
    }

    function loadPlonkEpochChangeFixture() public view returns (SphinxProofFixture memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/epoch_change_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixture));
    }

    function testValidEpochChangeProofCore() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        SphinxVerifier core = new SphinxVerifier();
        uint256 gasCost = gasleft();
        core.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);
        require(gasCost - gasleft() < 300000, "Too big gas cost");
    }

    function testValidInclusionProofCore() public {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        SphinxVerifier core = new SphinxVerifier();
        uint256 gasCost = gasleft();
        core.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);
        require(gasCost - gasleft() < 300000, "Too big gas cost");
    }

    // Negative tests
    function testFail_FakeProofInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        fixture.proof = fakeProof;
        wrapper.verifyInclusion(fixture);
    }

    function testFail_FakeProofEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        fixture.proof = fakeProof;
        wrapper.verifyEpochChange(fixture);
    }

    function testFail_FakePublicValuesInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length + 100);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyInclusion(fixture);
    }

    function testFail_FakePublicValuesEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyEpochChange(fixture);
    }

    function testFail_WrongVkValuesInclusion() public view {
        SphinxProofFixture memory epochChangeFixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory inner = inclusionFixture;
        inner.vkey = epochChangeFixture.vkey;
        // taking vk from epoch change for proof / public values from inclusion
        wrapper.verifyInclusion(inner);
    }

    function testFail_WrongVkValuesEpochChange() public {
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory epochChangefixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inner = epochChangefixture;
        inner.vkey = inclusionFixture.vkey;
        // taking vk from inclusion for proof / public values from epoch change
        wrapper.verifyEpochChange(inner);
    }

    function testFailInvalidSignerHashInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        // alter signer hash which is first 32 bytes
        fixture.publicValues[0] = 0xff;
        wrapper.verifyInclusion(fixture);
    }

    function testFailInvalidSignerHashEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        // alter signer hash which is first 32 bytes
        fixture.publicValues[0] = 0xff;
        wrapper.verifyEpochChange(fixture);
    }

    function testEpochChangeSignerHashUpdate() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        require(wrapper.getSignerHash() == bytes32(TestValidSignerHash), "Unexpected value of signer hash during setup");
        wrapper.verifyEpochChange(fixture);
        require(wrapper.getSignerHash() == bytes32(TestUpdatedSignerHash), "Signer hash was not updated");
    }
}
