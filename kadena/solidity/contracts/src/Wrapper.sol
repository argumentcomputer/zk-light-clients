pragma solidity ^0.8.25;

import {console} from "forge-std/Test.sol";
import {SphinxVerifier as SphinxPlonkVerifier} from "sphinx-contracts/SphinxVerifier.sol";
import "openzeppelin/access/Ownable.sol";

struct SphinxProofFixture {
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract Wrapper is SphinxPlonkVerifier, Ownable(msg.sender) {
    error ErrorUnexpectedLongestChainFixture();
    error ErrorUnexpectedSpvFixture();
    error ErrorUnexpectedSpvSubjectHash();
    error ErrorConfirmationWorkIsSmallerThanThreshold();
    error ErrorUnexpectedLayerHash();

    // state
    bytes32[] checkpoints;
    uint256 confirmation_work_threshold;

    constructor(uint256 confirmation_work_threshold_, bytes32[] memory checkpoints_) {
        // Kadena's Chainweb protocol setting
        require(checkpoints_.length >= 5);

        checkpoints = checkpoints_;
        confirmation_work_threshold = confirmation_work_threshold_;
    }

    // FIXME: This function is only for testing purposes!!!
    function set_head_checkpoint(bytes32 zero_checkpoint) public onlyOwner {
        checkpoints[0] = zero_checkpoint;
    }

    // FIXME: This function is only for testing purposes!!!
    function set_confirmation_work_threshold(uint256 threshold) public onlyOwner {
        confirmation_work_threshold = threshold;
    }

    // FIXME: This function is only for testing purposes!!!
    function set_tail_checkpoint(bytes32 target_checkpoint) public onlyOwner {
        checkpoints[checkpoints.length - 1] = target_checkpoint;
    }

    function rotate_checkpoints(bytes32 target_checkpoint) public onlyOwner {
        // drop hash from the tail, shift rest of hashes and write new checkpoint to the head
        uint256 index;
        for (index = 1; index < checkpoints.length; index++) {
            checkpoints[checkpoints.length - index] = checkpoints[checkpoints.length - index - 1];
        }
        checkpoints[0] = target_checkpoint;
    }

    function in_state(bytes32 checkpoint) private view returns (bool) {
        for (uint256 index = 0; index < checkpoints.length; index++) {
            if (checkpoint == checkpoints[index]) {
                return true;
            }
        }
        return false;
    }

    function get_current_checkpoints() public view returns (bytes32[] memory) {
        return checkpoints;
    }

    function executeCommonProofProcessingLogic(SphinxProofFixture memory fixture, bool is_fork) public {
        uint256 offset = 0;
        uint256 i = 0;

        // it reverts execution if core verification fails, so no special handling is required
        this.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);

        bytes memory confirmation_work = new bytes(32);
        for (i = 0; i < 32; i++) {
            confirmation_work[i] = fixture.publicValues[i];
        }
        offset += 32;

        bytes memory first_layer_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            first_layer_hash[i] = fixture.publicValues[i + offset];
        }
        offset += 32;

        bytes memory target_layer_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            target_layer_hash[i] = fixture.publicValues[i + offset];
        }
        offset += 32;

        if (uint256(bytes32(confirmation_work)) < confirmation_work_threshold) {
            revert ErrorConfirmationWorkIsSmallerThanThreshold();
        }

        // in regular case, the first layer hash should correspond to the latest checkpoint,
        // which is in the tail of the list
        if (bytes32(first_layer_hash) != checkpoints[checkpoints.length - 1]) {
            revert ErrorUnexpectedLayerHash();
        }

        // in case of fork, the first layer hash might correspond to arbitrary checkpoint,
        if (is_fork) {
            if (in_state(bytes32(first_layer_hash))) {
                set_tail_checkpoint(bytes32(target_layer_hash));
            } else {
                revert ErrorUnexpectedLayerHash();
            }
        } else {
            rotate_checkpoints(bytes32(target_layer_hash));
        }
    }

    function verifyLongestChainProof(SphinxProofFixture memory fixture) public {
        if (fixture.publicValues.length != 32 + 32 + 32) {
            revert ErrorUnexpectedLongestChainFixture();
        }

        executeCommonProofProcessingLogic(fixture, false);

        console.log("All checks have been passed. State has been updated");
    }

    function verifySpvProof(SphinxProofFixture memory fixture, bytes32 user_submitted_spv_subject_hash) public {
        if (fixture.publicValues.length != 32 + 32 + 32 + 32) {
            revert ErrorUnexpectedSpvFixture();
        }

        executeCommonProofProcessingLogic(fixture, false);

        // starting from 96 after confirmation_work, first_layer_hash, target_layer_hash (32 + 32 + 32)
        uint256 offset = 96;
        uint256 i = 0;
        bytes memory subject_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            subject_hash[i] = fixture.publicValues[i + offset];
        }

        if (bytes32(subject_hash) != user_submitted_spv_subject_hash) {
            revert ErrorUnexpectedSpvSubjectHash();
        }

        console.log("All checks have been passed. State has been updated");
    }

    /*
    function verifyLongestChainProofForkCase(SphinxProofFixture memory fixture) public {
        if (fixture.publicValues.length != 32 + 32 + 32) {
            revert ErrorUnexpectedLongestChainFixture();
        }

        executeCommonProofProcessingLogic(fixture, true);

        console.log("All checks have been passed. State has been updated");
    }

    function verifySpvProofForkCase(SphinxProofFixture memory fixture, bytes32 user_submitted_spv_subject_hash)
        public
    {
        if (fixture.publicValues.length != 32 + 32 + 32 + 32) {
            revert ErrorUnexpectedSpvFixture();
        }

        executeCommonProofProcessingLogic(fixture, true);

        // starting from 96 after confirmation_work, first_layer_hash, target_layer_hash (32 + 32 + 32)
        uint256 offset = 96;
        uint256 i = 0;
        bytes memory subject_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            subject_hash[i] = fixture.publicValues[i + offset];
        }

        if (bytes32(subject_hash) != user_submitted_spv_subject_hash) {
            revert ErrorUnexpectedSpvSubjectHash();
        }

        console.log("All checks have been passed. State has been updated");
    }*/
}
