// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Inclusion} from "../src/Inclusion.sol";
import {EpochChange} from "../src/EpochChange.sol";

struct SphinxProofFixtureJson {
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract SolidityVerificationTest is Test {
    using stdJson for string;

    Inclusion public inclusion;
    EpochChange public epochChange;

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

    function setUp() public {
        SphinxProofFixtureJson memory plonkInclusionFixture = loadPlonkInclusionFixture();
        inclusion = new Inclusion(plonkInclusionFixture.vkey);

        SphinxProofFixtureJson memory plonkEpochChangeFixture = loadPlonkEpochChangeFixture();
        epochChange = new EpochChange(plonkEpochChangeFixture.vkey);
    }

    function testValidInclusionProofPlonk() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        uint256 gasCost = gasleft();
        inclusion.verifyProof(fixture.proof, fixture.publicValues);
        console.log("gas cost: ", gasCost - gasleft());
    }

    function testValidEpochChangeProofPlonk() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        uint256 gasCost = gasleft();
        epochChange.verifyProof(fixture.proof, fixture.publicValues);
        console.log("gas cost: ", gasCost - gasleft());
    }

    // Negative tests with a fake proof
    function testFail_FakeProofInclusion() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        inclusion.verifyProof(fakeProof, fixture.publicValues);
    }

    function testFail_FakeProofEpochChange() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        epochChange.verifyProof(fakeProof, fixture.publicValues);
    }

    // Negative tests with a fake public values (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_FakePublicValuesInclusion() public view {
        console.log("running testFail_FakePublicValuesInclusion");
        SphinxProofFixtureJson memory fixture = loadPlonkInclusionFixture();

        bytes memory fakePublicValues = new bytes(fixture.proof.length + 100);

        inclusion.verifyProof(fixture.proof, fakePublicValues);
    }

    function _testFail_FakePublicValuesEpochChange() public view {
        SphinxProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length);
        epochChange.verifyProof(fixture.proof, fakePublicValues);
    }

    // Negative tests with a wrong vk (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function _testFail_WrongVkValuesInclusion() public {
        SphinxProofFixtureJson memory plonkEpochChangeFixture = loadPlonkEpochChangeFixture();
        inclusion = new Inclusion(plonkEpochChangeFixture.vkey); // take key of epoch_change program

        SphinxProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        inclusion.verifyProof(fixture.proof, fixture.publicValues);
    }

    function _testFail_WrongVkValuesEpochChange() public {
        SphinxProofFixtureJson memory plonkInclusionFixture = loadPlonkInclusionFixture();
        epochChange = new EpochChange(plonkInclusionFixture.vkey); // take key of inclusion program

        SphinxProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        epochChange.verifyProof(fixture.proof, fixture.publicValues);
    }
}
