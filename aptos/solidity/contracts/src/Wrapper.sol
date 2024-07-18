pragma solidity ^0.8.25;

import {console} from "forge-std/Test.sol";
import {SphinxVerifier as SphinxPlonkVerifier} from "sphinx-contracts/SphinxVerifier.sol";
import "openzeppelin/access/Ownable.sol";

struct SphinxProofFixture {
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

struct InclusionProofFixture {
    SphinxProofFixture sphinxFixture;
    bytes32 signerHash;
    bytes32 blockHeight;
    bytes32 valueHash;
}

struct EpochChangeProofFixture {
    SphinxProofFixture sphinxFixture;
}

contract Wrapper is SphinxPlonkVerifier, Ownable(msg.sender) {
    error ErrorUnexpectedSignerHash();

    bytes32 private signerHash;

    constructor(bytes32 signerHash_) {
        signerHash = signerHash_;
    }

    function setSignerHash(bytes32 newSignerHash) public onlyOwner {
        signerHash = newSignerHash;
    }

    function getSignerHash() public returns (bytes32) {
        return signerHash;
    }

    function verifyInclusion(InclusionProofFixture memory fixture) public view {
        // it reverts execution if core verification fails, so no special handing is required
        this.verifyProof(fixture.sphinxFixture.vkey, fixture.sphinxFixture.publicValues, fixture.sphinxFixture.proof);
        if (signerHash != fixture.signerHash) {
            revert ErrorUnexpectedSignerHash();
        }

        console.log("block height is: ", uint256(fixture.blockHeight));
        console.log("value hash is: ", uint256(fixture.valueHash));

        // allow funds transfer
    }

    function verifyEpochChange(EpochChangeProofFixture memory fixture) public {
        // it reverts execution if core verification fails, so no special handling is required
        this.verifyProof(fixture.sphinxFixture.vkey, fixture.sphinxFixture.publicValues, fixture.sphinxFixture.proof);

        // extract previous and new signer hashes from public values (we are safe here as input validation is performed in the core contract)
        bytes memory prevSignerHash = new bytes(32);
        bytes memory newSignerHash = new bytes(32);
        uint256 offset = 32;
        uint256 length = 32;
        for (uint8 i = 0; i < length; i++) {
            prevSignerHash[i] = fixture.sphinxFixture.publicValues[i];
            newSignerHash[i] = fixture.sphinxFixture.publicValues[i + offset];
        }

        if (signerHash != bytes32(prevSignerHash)) {
            revert ErrorUnexpectedSignerHash();
        }

        // update signer hash
        setSignerHash(bytes32(newSignerHash));
    }
}
