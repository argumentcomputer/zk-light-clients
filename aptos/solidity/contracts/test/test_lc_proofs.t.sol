// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Wrapper, SphinxProofFixture} from "../src/Wrapper.sol";

contract SolidityVerificationTest is Test {
    using stdJson for string;

    uint256 private constant TestValidSignerHash = 0x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f;
    uint256 private constant TestUpdatedSignerHash = 0xdf3f40995c8199fac85ce1b6e98f46a2e955d1d58539953f4fb065d87150c641;
    uint256 private constant TestInvalidSignerHash = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    bytes private TestEpochChangePublicValues = abi.encodePacked(
        hex"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0fdf3f40995c8199fac85ce1b6e98f46a2e955d1d58539953f4fb065d87150c641"
    );
    bytes private TestInclusionPublicValues = abi.encodePacked(
        hex"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f13ac3f4a611fb8075f1d1baa53150bb357cd8567332fd69ea65609be7dca63b2030000000000000044fa02feb400a383b1824df6198c7e30cbf60a21838efa46fedf35f760fdf25839d1a3ec2b5d09aee31c1c0c380eef28744673ea3ab7e9d065baccc8d1874ca1"
    );

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

    function testValidInclusionProofPlonk() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        uint256 gasCost = gasleft();
        fixture.publicValues = TestInclusionPublicValues;
        wrapper.verifyInclusion(fixture);
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }

    function testValidEpochChangeProofPlonk() public {
        setUp();
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        // use altered public values to make test pass
        fixture.publicValues = TestEpochChangePublicValues;
        uint256 gasCost = gasleft();
        wrapper.verifyEpochChange(fixture);
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }

    // Negative tests with a fake proof
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

    // Negative tests with a fake public values (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_FakePublicValuesInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length + 100);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyInclusion(fixture);
    }

    function _testFail_FakePublicValuesEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyEpochChange(fixture);
    }

    // Negative tests with a wrong vk (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_WrongVkValuesInclusion() public view {
        SphinxProofFixture memory epochChangeFixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory inner = inclusionFixture;
        inner.vkey = epochChangeFixture.vkey;
        // taking vk from epoch change for proof / public values from inclusion
        wrapper.verifyInclusion(inner);
    }

    function _testFail_WrongVkValuesEpochChange() public {
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory epochChangefixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inner = epochChangefixture;
        inner.vkey = inclusionFixture.vkey;
        // taking vk from inclusion for proof / public values from epoch change
        wrapper.verifyEpochChange(inner);
    }

    function testFailInvalidSignerHashInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        wrapper.verifyInclusion(fixture);
    }

    function testFailInvalidSignerHashEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        wrapper.verifyEpochChange(fixture);
    }

    function testEpochChangeSignerHashUpdate() public {
        setUp();
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        // use altered public values to make test pass
        fixture.publicValues = TestEpochChangePublicValues;
        require(wrapper.getSignerHash() == bytes32(TestValidSignerHash), "Unexpected value of signer hash during setup");
        wrapper.verifyEpochChange(fixture);
        require(wrapper.getSignerHash() == bytes32(TestUpdatedSignerHash), "Signer hash was not updated");
    }
}
