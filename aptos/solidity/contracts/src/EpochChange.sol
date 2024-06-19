pragma solidity ^0.8.25;

import {SP1Verifier as SP1PlonkVerifier} from "sphinx-contracts/SP1Verifier.sol";

contract EpochChange is SP1PlonkVerifier {
    bytes32 public epochChangeProgramVkey;

    constructor(bytes32 _epochChangeProgramVkey) {
        epochChangeProgramVkey = _epochChangeProgramVkey;
    }

    function verifyProof(bytes memory proof, bytes memory publicValues) public view {
        this.verifyProof(epochChangeProgramVkey, publicValues, proof);
    }
}
