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
        // initial state
        bytes32[] memory checkpoints = new bytes32[](5);
        checkpoints[0] = bytes32(0x0000000000000000000000000000000000000000000000000000000000000001);
        checkpoints[1] = bytes32(0x0000000000000000000000000000000000000000000000000000000000000002);
        checkpoints[2] = bytes32(0x0000000000000000000000000000000000000000000000000000000000000003);
        checkpoints[3] = bytes32(0x0000000000000000000000000000000000000000000000000000000000000004);
        checkpoints[4] = bytes32(0x0000000000000000000000000000000000000000000000000000000000000005);

        uint256 confirmation_work_threshold = 0x596e6483a7e9188e289af6012de83766283712e3ad57bf03dd03000000000001;

        wrapper = new Wrapper(confirmation_work_threshold, checkpoints);
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

    function testSuccessfulLongestChainVerification() public {
        SphinxProofFixture memory fixture = loadPlonkLongestChainFixture();
        bytes memory confirmation_work = new bytes(32);
        uint256 offset = 0;
        uint256 i = 0;
        for (i = 0; i < 32; i++) {
            confirmation_work[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_confirmation_work_threshold(uint256(bytes32(confirmation_work)));

        bytes memory head_checkpoint = new bytes(32);
        offset = 32;
        for (i = 0; i < 32; i++) {
            head_checkpoint[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_head_checkpoint(bytes32(head_checkpoint));

        wrapper.verifyLongestChainProof(fixture);

        // check state rotation
        bytes memory tail_checkpoint = new bytes(32);
        offset = 64;
        for (i = 0; i < 32; i++) {
            tail_checkpoint[i] = fixture.publicValues[i + offset];
        }

        bytes32[] memory checkpoints = wrapper.get_current_checkpoints();
        require(checkpoints[0] == 0x0000000000000000000000000000000000000000000000000000000000000002);
        require(checkpoints[1] == 0x0000000000000000000000000000000000000000000000000000000000000003);
        require(checkpoints[2] == 0x0000000000000000000000000000000000000000000000000000000000000004);
        require(checkpoints[3] == 0x0000000000000000000000000000000000000000000000000000000000000005);
        require(checkpoints[4] == bytes32(tail_checkpoint));
    }

    function testSuccessfulSpvVerification() public {
        SphinxProofFixture memory fixture = loadPlonkSpvFixture();
        bytes memory confirmation_work = new bytes(32);
        uint256 offset = 0;
        uint256 i = 0;
        for (i = 0; i < 32; i++) {
            confirmation_work[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_confirmation_work_threshold(uint256(bytes32(confirmation_work)));

        bytes memory head_checkpoint = new bytes(32);
        offset = 32;
        for (i = 0; i < 32; i++) {
            head_checkpoint[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_head_checkpoint(bytes32(head_checkpoint));

        offset = 96;
        bytes memory subject_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            subject_hash[i] = fixture.publicValues[i + offset];
        }
        wrapper.verifySpvProof(fixture, bytes32(subject_hash));

        // check state rotation
        bytes memory tail_checkpoint = new bytes(32);
        offset = 64;
        for (i = 0; i < 32; i++) {
            tail_checkpoint[i] = fixture.publicValues[i + offset];
        }

        bytes32[] memory checkpoints = wrapper.get_current_checkpoints();
        require(checkpoints[0] == 0x0000000000000000000000000000000000000000000000000000000000000002);
        require(checkpoints[1] == 0x0000000000000000000000000000000000000000000000000000000000000003);
        require(checkpoints[2] == 0x0000000000000000000000000000000000000000000000000000000000000004);
        require(checkpoints[3] == 0x0000000000000000000000000000000000000000000000000000000000000005);
        require(checkpoints[4] == bytes32(tail_checkpoint));
    }

    function testFailSmallerConfirmationWorkThreshold1() public {
        SphinxProofFixture memory fixture = loadPlonkSpvFixture();
        bytes memory head_checkpoint = new bytes(32);
        uint256 offset = 32;
        uint256 i = 0;
        for (i = 0; i < 32; i++) {
            head_checkpoint[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_head_checkpoint(bytes32(head_checkpoint));

        offset = 96;
        i = 0;
        bytes memory subject_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            subject_hash[i] = fixture.publicValues[i + offset];
        }
        wrapper.verifySpvProof(fixture, bytes32(subject_hash));
    }

    function testFailSmallerConfirmationWorkThreshold2() public {
        SphinxProofFixture memory fixture = loadPlonkLongestChainFixture();
        bytes memory head_checkpoint = new bytes(32);
        uint256 offset = 32;
        uint256 i = 0;
        for (i = 0; i < 32; i++) {
            head_checkpoint[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_head_checkpoint(bytes32(head_checkpoint));

        wrapper.verifyLongestChainProof(fixture);
    }

    function testSuccessfulLongestChainVerificationForkCase() public {
        SphinxProofFixture memory fixture = loadPlonkLongestChainFixture();
        bytes memory confirmation_work = new bytes(32);
        uint256 offset = 0;
        uint256 i = 0;
        for (i = 0; i < 32; i++) {
            confirmation_work[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_confirmation_work_threshold(uint256(bytes32(confirmation_work)));

        bytes memory head_checkpoint = new bytes(32);
        offset = 32;
        for (i = 0; i < 32; i++) {
            head_checkpoint[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_head_checkpoint(bytes32(head_checkpoint));

        wrapper.verifyLongestChainProofForkCase(fixture);

        // check state rotation
        bytes memory tail_checkpoint = new bytes(32);
        offset = 64;
        for (i = 0; i < 32; i++) {
            tail_checkpoint[i] = fixture.publicValues[i + offset];
        }

        bytes32[] memory checkpoints = wrapper.get_current_checkpoints();
        require(checkpoints[0] == bytes32(head_checkpoint));
        require(checkpoints[1] == 0x0000000000000000000000000000000000000000000000000000000000000002);
        require(checkpoints[2] == 0x0000000000000000000000000000000000000000000000000000000000000003);
        require(checkpoints[3] == 0x0000000000000000000000000000000000000000000000000000000000000004);
        require(checkpoints[4] == bytes32(tail_checkpoint));
    }

    function testSuccessfulSpvVerificationForkCase() public {
        SphinxProofFixture memory fixture = loadPlonkSpvFixture();
        bytes memory confirmation_work = new bytes(32);
        uint256 offset = 0;
        uint256 i = 0;
        for (i = 0; i < 32; i++) {
            confirmation_work[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_confirmation_work_threshold(uint256(bytes32(confirmation_work)));

        bytes memory head_checkpoint = new bytes(32);
        offset = 32;
        for (i = 0; i < 32; i++) {
            head_checkpoint[i] = fixture.publicValues[i + offset];
        }

        wrapper.set_head_checkpoint(bytes32(head_checkpoint));

        offset = 96;
        bytes memory subject_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            subject_hash[i] = fixture.publicValues[i + offset];
        }
        wrapper.verifySpvProofForkCase(fixture, bytes32(subject_hash));

        // check state rotation
        bytes memory tail_checkpoint = new bytes(32);
        offset = 64;
        for (i = 0; i < 32; i++) {
            tail_checkpoint[i] = fixture.publicValues[i + offset];
        }

        bytes32[] memory checkpoints = wrapper.get_current_checkpoints();
        require(checkpoints[0] == bytes32(head_checkpoint));
        require(checkpoints[1] == 0x0000000000000000000000000000000000000000000000000000000000000002);
        require(checkpoints[2] == 0x0000000000000000000000000000000000000000000000000000000000000003);
        require(checkpoints[3] == 0x0000000000000000000000000000000000000000000000000000000000000004);
        require(checkpoints[4] == bytes32(tail_checkpoint));
    }
}
