pragma solidity ^0.8.25;

import {SphinxVerifier as SphinxPlonkVerifier} from "sphinx-contracts/SphinxVerifier.sol";

contract Inclusion is SphinxPlonkVerifier {
    bytes32 public inclusionProgramVkey;

    constructor(bytes32 _inclusionProgramVkey) {
        inclusionProgramVkey = _inclusionProgramVkey;
    }

    function verifyProof(bytes memory proof, bytes memory publicValues) public view {
        this.verifyProof(inclusionProgramVkey, publicValues, proof);
    }
}
