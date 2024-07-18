pragma solidity ^0.8.25;

import {console} from "forge-std/Test.sol";
import {SphinxVerifier as SphinxPlonkVerifier} from "sphinx-contracts/SphinxVerifier.sol";

struct SphinxProofFixture {
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

struct InclusionProofFixture {
    SphinxProofFixture sphinxFixture;
    bytes32 signerHash;
}

struct EpochChangeProofFixture {
    SphinxProofFixture sphinxFixture;
    bytes32 signerHash;
}

contract Wrapper is SphinxPlonkVerifier {
    error ErrorUnexpectedSignerHash();

    bytes32 public signerHash;

    constructor(bytes32 signerHash_) {
        signerHash = signerHash_;
    }

    function verifyInclusion(
        InclusionProofFixture memory fixture
    ) public view {
        // it reverts execution if core verification fails, so no special handing is required
        this.verifyProof(fixture.sphinxFixture.vkey, fixture.sphinxFixture.publicValues, fixture.sphinxFixture.proof);
        if (signerHash != fixture.signerHash) {
            revert ErrorUnexpectedSignerHash();
        }
    }

    function verifyEpochChange(
        EpochChangeProofFixture memory fixture
    ) public view {
        // it reverts execution if core verification fails, so no special handling is required
        this.verifyProof(fixture.sphinxFixture.vkey, fixture.sphinxFixture.publicValues, fixture.sphinxFixture.proof);
        if (signerHash != fixture.signerHash) {
            revert ErrorUnexpectedSignerHash();
        }
    }
}
