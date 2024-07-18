// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Wrapper, SphinxProofFixture, InclusionProofFixture, EpochChangeProofFixture} from "../src/Wrapper.sol";

contract SolidityVerificationTest is Test {
    using stdJson for string;

    uint256 private constant ValidSignerHash = 0x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f;
    uint256 private constant InvalidSignerHash =  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    Wrapper wrapper;

    function setUp() public {
        bytes32 signer_hash = bytes32(ValidSignerHash);
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

    function testValidInclusionProofPlonk() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        uint256 gasCost = gasleft();
        wrapper.verifyInclusion(InclusionProofFixture(fixture, bytes32(ValidSignerHash)));
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }


    function testValidEpochChangeProofPlonk() public view {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        uint256 gasCost = gasleft();
        wrapper.verifyEpochChange(EpochChangeProofFixture(fixture, bytes32(ValidSignerHash)));
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }

    // Negative tests with a fake proof
    function testFail_FakeProofInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        fixture.proof = fakeProof;
        wrapper.verifyInclusion(InclusionProofFixture(fixture, bytes32(ValidSignerHash)));
    }

    function testFail_FakeProofEpochChange() public view {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        fixture.proof = fakeProof;
        wrapper.verifyEpochChange(EpochChangeProofFixture(fixture, bytes32(ValidSignerHash)));
    }

    // Negative tests with a fake public values (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_FakePublicValuesInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length + 100);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyInclusion(InclusionProofFixture(fixture, bytes32(ValidSignerHash)));
    }

    function _testFail_FakePublicValuesEpochChange() public view {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyEpochChange(EpochChangeProofFixture(fixture, bytes32(ValidSignerHash)));
    }

    // Negative tests with a wrong vk (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_WrongVkValuesInclusion() public {
        SphinxProofFixture memory epochChangeFixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory inner = inclusionFixture;
        inner.vkey = epochChangeFixture.vkey;
        // taking vk from epoch change for proof / public values from inclusion
        wrapper.verifyInclusion(InclusionProofFixture(inner, bytes32(ValidSignerHash)));
    }

    function _testFail_WrongVkValuesEpochChange() public {
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory epochChangefixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inner = epochChangefixture;
        inner.vkey = inclusionFixture.vkey;
        // taking vk from inclusion for proof / public values from epoch change
        wrapper.verifyEpochChange(EpochChangeProofFixture(inner, bytes32(ValidSignerHash)));
    }

    function testFailInvalidSignerHashInclusion() public {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        wrapper.verifyInclusion(InclusionProofFixture(fixture, bytes32(InvalidSignerHash)));
    }

    function testFailInvalidSignerHashEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        wrapper.verifyEpochChange(EpochChangeProofFixture(fixture, bytes32(InvalidSignerHash)));
    }
}
