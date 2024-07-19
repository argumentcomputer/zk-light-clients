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
    error ErrorUnexpectedSignerHash();
    error ErrorUnexpectedInclusionFixture();
    error ErrorUnexpectedEpochChangeFixture();

    bytes32 private signerHash;

    constructor(bytes32 signerHash_) {
        signerHash = signerHash_;
    }

    function setSignerHash(bytes32 newSignerHash) public onlyOwner {
        signerHash = newSignerHash;
    }

    function getSignerHash() public view returns (bytes32) {
        return signerHash;
    }

    function verifyInclusion(SphinxProofFixture memory fixture) public view {
        if (fixture.publicValues.length != 32 + 32 + 32 + 32 + 8) {
            revert ErrorUnexpectedInclusionFixture();
        }

        // it reverts execution if core verification fails, so no special handling is required
        this.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);

        uint256 offset = 0;
        uint256 i = 0;

        bytes memory signerHashFixture = new bytes(32);
        for (i = 0; i < 32; i++) {
            signerHashFixture[i] = fixture.publicValues[i];
        }
        offset += 32;

        bytes memory merkleRootHash = new bytes(32);
        for (i = 0; i < 32; i++) {
            merkleRootHash[i] = fixture.publicValues[i + offset];
        }
        offset += 32;

        bytes memory blockId = new bytes(8);
        for (i = 0; i < 8; i++) {
            blockId[i] = fixture.publicValues[i + offset];
        }
        offset += 8;

        bytes memory key = new bytes(32);
        for (i = 0; i < 32; i++) {
            key[i] = fixture.publicValues[i + offset];
        }
        offset += 32;

        bytes memory value = new bytes(32);
        for (i = 0; i < 32; i++) {
            value[i] = fixture.publicValues[i + offset];
        }

        if (signerHash != bytes32(signerHashFixture)) {
            revert ErrorUnexpectedSignerHash();
        }

        console.log("merkle root hash is: ", uint256(bytes32(merkleRootHash)));
        console.log("block identifier is: ", uint256(bytes32(blockId)));
        console.log("key is: ", uint256(bytes32(key)));
        console.log("value is: ", uint256(bytes32(value)));

        // allow funds transfer
    }

    function verifyEpochChange(SphinxProofFixture memory fixture) public {
        if (fixture.publicValues.length != 64) {
            revert ErrorUnexpectedEpochChangeFixture();
        }

        // it reverts execution if core verification fails, so no special handling is required
        this.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);

        // extract previous and new signer hashes from public values (we are safe here as input validation is performed in the core contract)
        bytes memory prevSignerHash = new bytes(32);
        bytes memory newSignerHash = new bytes(32);
        uint256 offset = 32;
        uint256 length = 32;
        for (uint8 i = 0; i < length; i++) {
            prevSignerHash[i] = fixture.publicValues[i];
            newSignerHash[i] = fixture.publicValues[i + offset];
        }

        if (signerHash != bytes32(prevSignerHash)) {
            revert ErrorUnexpectedSignerHash();
        }

        // update signer hash
        setSignerHash(bytes32(newSignerHash));
    }
}
