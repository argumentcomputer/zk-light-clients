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

}
