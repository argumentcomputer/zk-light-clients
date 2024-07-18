pragma solidity ^0.8.25;

import {SphinxVerifier as SphinxPlonkVerifier} from "sphinx-contracts/SphinxVerifier.sol";

contract Wrapper is SphinxPlonkVerifier {
    error ErrorUnexpectedSignerHash();

    bytes32 public this_signer_hash;

    constructor(bytes32 signer_hash) {
        this_signer_hash = signer_hash;
    }

    function verify(
        bytes32 vk,
        bytes memory proof,
        bytes memory publicValues,
        bytes32 signer_hash
    ) public view {
        this.verifyProof(vk, publicValues, proof); // it reverts execution if core verification fails
        if (this_signer_hash != signer_hash) {
            revert ErrorUnexpectedSignerHash();
        }
    }
}
