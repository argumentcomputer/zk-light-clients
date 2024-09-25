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



        console.log("All checks passed. Funds transfer is allowed");
    }

    function reverse256(uint256 input) public pure returns (uint256 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
        | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
        | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
        | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
        | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }

    function from_be(bytes4 input) public pure returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < 4; i++) {
            result = (result << 8) + reverse256(uint256(bytes32((input[i] & 0xff))));
        }
        return result;
    }

    function verifySpvProof(SphinxProofFixture memory fixture, bytes32 expected_spv_subject_hash) public view {
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

        bytes memory unknown_data = new bytes(8);
        for (i = 0; i < 8; i++) {
            unknown_data[i] = fixture.publicValues[i + offset];
        }
        offset += 8;

        bytes memory spv_subject_length_bytes = new bytes(4);
        for (i = 0; i < 4; i++) {
            spv_subject_length_bytes[i] = fixture.publicValues[i + offset];
        }
        offset += 4;

        uint256 spv_subject_length = from_be(bytes4(spv_subject_length_bytes));

        bytes memory spv_subject = new bytes(spv_subject_length);
        for (i = 0; i < spv_subject_length; i++) {
            spv_subject[i] = fixture.publicValues[i + offset];
        }
        offset += spv_subject_length;

        console.log("confirmation_work: ");
        console.logBytes32(bytes32(confirmation_work));
        console.log("first_layer_hash: ");
        console.logBytes32(bytes32(first_layer_hash));
        console.log("target_layer_hash: ");
        console.logBytes32(bytes32(target_layer_hash));
        console.log("unknown data: ");
        console.logBytes8(bytes8(unknown_data));
        console.log("length of subject: ", spv_subject_length);
        console.log("subject: ", spv_subject);

        // parse subject

        //if (signerHash != expected_spv_subject_hash) {
        //    revert ErrorUnexpectedSignerHash();
        //}
    }
}
