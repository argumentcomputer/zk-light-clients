pragma solidity ^0.8.25;

import {SphinxVerifier as SphinxPlonkVerifier} from "sphinx-contracts/SphinxVerifier.sol";

contract EpochChange is SphinxPlonkVerifier {
    bytes32 public epochChangeProgramVkey;

    constructor(bytes32 _epochChangeProgramVkey) {
        epochChangeProgramVkey = _epochChangeProgramVkey;
    }

    function verifyProof(bytes memory proof, bytes memory publicValues) public view {
        this.verifyProof(epochChangeProgramVkey, publicValues, proof);
    }
}
