// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Inclusion} from "../src/Inclusion.sol";
import {EpochChange} from "../src/EpochChange.sol";

struct SP1ProofFixtureJson {
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract SolidityVerificationTest is Test {
    using stdJson for string;

    Inclusion public inclusion;
    EpochChange public epochChange;

    function loadPlonkInclusionFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/inclusion_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function loadPlonkEpochChangeFixture() public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/epoch_change_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory plonkInclusionFixture = loadPlonkInclusionFixture();
        inclusion = new Inclusion(plonkInclusionFixture.vkey);

        SP1ProofFixtureJson memory plonkEpochChangeFixture = loadPlonkEpochChangeFixture();
        epochChange = new EpochChange(plonkEpochChangeFixture.vkey);
    }

    function testValidInclusionProofPlonk() public view {
        SP1ProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        uint256 gasCost = gasleft();
        inclusion.verifyProof(fixture.proof, fixture.publicValues);
        console.log("gas cost: ", gasCost - gasleft());
    }

    function testValidEpochChangeProofPlonk() public view {
        SP1ProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        uint256 gasCost = gasleft();
        epochChange.verifyProof(fixture.proof, fixture.publicValues);
        console.log("gas cost: ", gasCost - gasleft());
    }

    function testFail_InclusionProofPlonk() public view {
        SP1ProofFixtureJson memory fixture = loadPlonkInclusionFixture();
        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);
        inclusion.verifyProof(fakeProof, fixture.publicValues);
    }

    function testFail_EpochChangeProofPlonk() public view {
        SP1ProofFixtureJson memory fixture = loadPlonkEpochChangeFixture();
        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);
        inclusion.verifyProof(fakeProof, fixture.publicValues);
    }
}
