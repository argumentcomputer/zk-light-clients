// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Wrapper, SphinxProofFixture} from "../src/Wrapper.sol";
import {SphinxVerifier} from "sphinx-contracts/SphinxVerifier.sol";

contract SolidityVerificationTest is Test {
    using stdJson for string;

    Wrapper wrapper;

    function setUp() public {
        wrapper = new Wrapper();
    }

    function loadPlonkLongestChainFixture() public view returns (SphinxProofFixture memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/longest_chain_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixture));
    }

    function loadPlonkSpvFixture() public view returns (SphinxProofFixture memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/spv_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixture));
    }

    function testValidSpvProofCore() public {
        SphinxProofFixture memory fixture = loadPlonkSpvFixture();
        SphinxVerifier core = new SphinxVerifier();
        uint256 gasCost = gasleft();
        core.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);
        require(gasCost - gasleft() < 300000, "Too big gas cost");
    }

    function testValidLongestChainProofCore() public {
        SphinxProofFixture memory fixture = loadPlonkLongestChainFixture();
        SphinxVerifier core = new SphinxVerifier();
        uint256 gasCost = gasleft();
        core.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);
        require(gasCost - gasleft() < 300000, "Too big gas cost");
    }

    function testDebug() public {
        SphinxProofFixture memory fixture = loadPlonkSpvFixture();
        wrapper.verifySpvProof(fixture, bytes32(0x256348dcc4564a102e6c913bf04b8dc6bc1e8325a8bbc71b49808a49bca7340a));
    }
}
