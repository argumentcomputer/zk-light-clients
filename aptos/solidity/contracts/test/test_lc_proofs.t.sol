// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Wrapper} from "../src/Wrapper.sol";

struct SphinxProofFixtureJson {
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract SolidityVerificationTest is Test {
    using stdJson for string;

    uint256 private constant ValidSignerHash = 0x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f;
    uint256 private constant InvalidSignerHash =  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    Wrapper wrapper;

    function setUp() public {
        bytes32 signer_hash = bytes32(ValidSignerHash);
        wrapper = new Wrapper(signer_hash);
    }


    function loadPlonkInclusionFixture() public view returns (SphinxProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/inclusion_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixtureJson));
    }

    function loadPlonkEpochChangeFixture() public view returns (SphinxProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/epoch_change_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixtureJson));
    }

    function testValidInclusionProofPlonk() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        uint256 gasCost = gasleft();
        wrapper.verify(fixture.vkey, fixture.proof, fixture.publicValues, bytes32(ValidSignerHash));
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }

    function testValidEpochChangeProofPlonk() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        uint256 gasCost = gasleft();
        wrapper.verify(fixture.vkey, fixture.proof, fixture.publicValues, bytes32(ValidSignerHash));
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }

    // Negative tests with a fake proof
    function testFail_FakeProofInclusion() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        wrapper.verify(fixture.vkey, fakeProof, fixture.publicValues, bytes32(ValidSignerHash));
    }

    function testFail_FakeProofEpochChange() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        wrapper.verify(fixture.vkey, fakeProof, fixture.publicValues, bytes32(ValidSignerHash));
    }

    // Negative tests with a fake public values (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_FakePublicValuesInclusion() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length + 100);
        wrapper.verify(fixture.vkey, fixture.proof, fakePublicValues, bytes32(ValidSignerHash));
    }

    function _testFail_FakePublicValuesEpochChange() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length);
        wrapper.verify(fixture.vkey, fixture.proof, fakePublicValues, bytes32(ValidSignerHash));
    }

    // Negative tests with a wrong vk (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_WrongVkValuesInclusion() public {
        SphinxProofFixtureJson memory epochChangeFixture = loadPlonkEpochChangeFixture();
        SphinxProofFixtureJson memory inclusionFixture = loadPlonkInclusionFixture();
        // taking vk from epoch change for proof / public values from inclusion
        wrapper.verify(epochChangeFixture.vkey, inclusionFixture.proof, inclusionFixture.publicValues, bytes32(ValidSignerHash));
    }

    function _testFail_WrongVkValuesEpochChange() public {
        SphinxProofFixtureJson memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixtureJson memory epochChangefixture = loadPlonkEpochChangeFixture();
        // taking vk from inclusion for proof / public values from epoch change
        wrapper.verify(inclusionFixture.vkey, epochChangefixture.proof, epochChangefixture.publicValues, bytes32(ValidSignerHash));
    }
}
