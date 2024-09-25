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

    // state
    // set_state(state)
    // get_state()

    function verifyLongestChainProof(SphinxProofFixture memory fixture) public view {

    }

    function verifySpvProof(SphinxProofFixture memory fixture, bytes32 memory hash) public view {

    }
}
