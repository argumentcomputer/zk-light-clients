pragma solidity ^0.8.25;

import {SP1Verifier as SP1PlonkVerifier} from "../src/plonk/SP1Verifier.sol";

contract Inclusion is SP1PlonkVerifier {
    bytes32 public inclusionProgramVkey;

    constructor(bytes32 _inclusionProgramVkey) {
        inclusionProgramVkey = _inclusionProgramVkey;
    }

    function verifyProof(bytes memory proof, bytes memory publicValues) public view {
        this.verifyProof(inclusionProgramVkey, publicValues, proof);
    }
}
