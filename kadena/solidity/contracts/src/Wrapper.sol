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

    //uint256[] memory checkpoints;
    //bytes32 confirmation_work_threshold;

    //function setUp() {

    //}

    // state
    // set_state(state)
    // get_state()

    function verifyLongestChainProof(SphinxProofFixture memory fixture) public view {
        if (fixture.publicValues.length != 32 + 32 + 32) {
            revert ErrorUnexpectedLongestChainFixture();
        }

        // it reverts execution if core verification fails, so no special handling is required
        this.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);

        uint256 offset = 0;
        uint256 i = 0;

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

        console.log("confirmation_work: ");
        console.logBytes32(bytes32(confirmation_work));
        console.log("first_layer_hash: ");
        console.logBytes32(bytes32(first_layer_hash));
        console.log("target_layer_hash: ");
        console.logBytes32(bytes32(target_layer_hash));

        // TODO: implement checks

        console.log("All checks passed");
    }

    function verifySpvProof(SphinxProofFixture memory fixture, bytes32 user_submitted_spv_subject_hash) public view {
        if (fixture.publicValues.length < 32 + 32 + 32 + 8 + 4) {
            revert ErrorUnexpectedSpvFixture();
        }

        // it reverts execution if core verification fails, so no special handling is required
        this.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);

        uint256 offset = 0;
        uint256 i = 0;

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

        bytes memory subject_hash = new bytes(32);
        for (i = 0; i < 32; i++) {
            subject_hash[i] = fixture.publicValues[i + offset];
        }
        offset += 32;

        console.log("confirmation_work: ");
        console.logBytes32(bytes32(confirmation_work));
        console.log("first_layer_hash: ");
        console.logBytes32(bytes32(first_layer_hash));
        console.log("target_layer_hash: ");
        console.logBytes32(bytes32(target_layer_hash));
        console.log("subject hash: ");
        console.logBytes32(bytes32(subject_hash));

        // TODO: implement checks

        if (bytes32(subject_hash) != user_submitted_spv_subject_hash) {
            revert ErrorUnexpectedSpvSubjectHash();
        }

        console.log("All checks passed");
    }
}
