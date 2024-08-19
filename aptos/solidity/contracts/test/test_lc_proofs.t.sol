// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Wrapper, SphinxProofFixture} from "../src/Wrapper.sol";
import {SphinxVerifier} from "sphinx-contracts/SphinxVerifier.sol";

contract SolidityVerificationTest is Test {
    using stdJson for string;

    uint256 private constant TestValidSignerHash = 0x205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ec;
    uint256 private constant TestUpdatedSignerHash = 0xc071f215064bfe6f1c24295135199ce6f6dec2974115fad50989e666915453ad;

    // valid epoch change fixture for testing purposes
    bytes private TestEpochChangeVkey =
        abi.encodePacked(hex"00eea0650222f7e5bb6a2fe57c0e0e504d1df8b3d848d5116174a8703d228c94");
    bytes private TestEpochChangePublicValues = abi.encodePacked(
        hex"205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ecc071f215064bfe6f1c24295135199ce6f6dec2974115fad50989e666915453ad"
    );
    bytes private TestEpochChangeProof = abi.encodePacked(
        hex"0ab2a3f76f07021cf8355041b0e80a079ea24e9fe36886d2f2b0fe9f6ca8c1d11460d09b1ce1d3cf50cd5cc0760669b8e8f5629fc0d426050d380152451cceb42b863aca64cbe9e67344a5f4851b78dfc55b157cfb75ac6df0a6e82b64487bf20cfa2c2a004cbaa685d0743c75f31afee3fa2b89a910c41d616a2a0c805cd4f8190e84bf17686dbb04c74b27ba0e79b46c06901c79931bcdd9e36c0aa192398f1b60a06cdcbeef2a2c0d7be5fdcc101cb9de1625966661f763b7f4d380f8c77b1aeca50fea9474242c8342665be9e2b36f99e589c61b5af219c72ac20d7a4f6d01f47105ead257b6a8d4cbad6f0025f9499da47b185a6a29be2a0976350fd3c52978a822a071e2c4828b7a1fdef0745a641e85f0a98d526ab811bc94846a17f220618a59cd47622fb2066de0817b53f74dbf9b496b6c9346ac9bf8ea3e50667d16500b36c88cc53c95a61989eae61bd2d7cabf39fa295d0e303c1ae04e14aa202c98c3188b2bae90cd20f7586a95abf55c943b669238561cd66ca1b4a31ab9d4121da63c61700abc8cd5dc10168781407667ccc4a5c14010bf62e9b969423b7011f55c5a114b4aa35b5b32a4371ec41a7e6c0a99bb8ed9928f1c81d38c1d65981ea57c37621be5cf357a0694051db17a310d87d81824a728960b20a29579ab5509713c982d7b5457bfd6cf995d2093b37070fa8d81e7f130ef35599a3bd6130c1bbec9cb0352e1986e59aa4a0480cdca6b0a280cbc0435dc005beec32483eb3a2c178b87931b1014a8b424cc19c992b5a6c17aa54b013f7401865edc52c1dec226c2b9aa2a25f98925a2171e5e63bb78cb13a30b6099c5cba62a8ff92265f7082a79086c6d603ab1e7e0950d707acb3bc6a929cc5dacd0102b3b7aa29253fac921e2a94b75536d62e6a6585c0f96974a236f2740fa0d249fb5ad4facfe3cc4d605901c9cf8931d8f2b87db2535a44f14e2c3e01ef4b98e8ea259c1decd2a4ee01e0406c20e0523faddd984577b94f688517d0d930346d18ed029331b8818e2f6168201bfb0ecc95d72b83957e916e5d79a5aaafbd2e6018fc9164b369cd732231dc4501b768ca50f25b7655a28ad83fd1bea600fa5e8cdd59c776adc17bd36890c30e071749d843cb7a1d2f964ad6e4a01d5595b848f5faef51c286a8b01e77015a5c0d1b9d05e0b287b288c582fb3dfd8d108370b7e1873630bb2aec4f4c869"
    );

    // valid inclusion fixture for testing purposes
    bytes private TestInclusionVkey =
        abi.encodePacked(hex"00336c570224c00161ca7b3c275c24f3968aa09086c31d09d98691bce109f4f6");
    bytes private TestInclusionPublicValues = abi.encodePacked(
        hex"205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ec5c1e92bfe65b6200f1f7383d8fe6be26f70e05d784df4a170e38eb6be236145c020202020202020202020202020202020202020202020202020202020202020244fa02feb400a383b1824df6198c7e30cbf60a21838efa46fedf35f760fdf25839d1a3ec2b5d09aee31c1c0c380eef28744673ea3ab7e9d065baccc8d1874ca1"
    );
    bytes private TestInclusionProof = abi.encodePacked(
        hex"a855844200667c07f515143095356049737e6657b90cadabb9e75b17ac3a9dca9ee5e7f52c8b43ff6d992c9eff8ee2c0628b15a5399f549188867048db7c0367e7c79b9d233c2374c0a912c170f58bf362342adfd7f09ce84f7000ac4f065aae3c1502172df54ea50bdb9ed329044aef6350f53a2233c71bfd0c6b465a667b6ffe5424301eaa330341702e7afd6ae68033b0707744b5e50a149d59af317b8e52401af21d102acdfe11036570f2d0691342614e3ddd6549cfd67729fb189140573e946032218c0fb39ec5093827752c7b54ef6468e2f86f6ee9e8405467a30388ae7f42ff08857c2a06da015595c42b9df69c4937ff73f22e2d954ad067ae45a04148782c0e310ecba87e87e0a0b6e5ecc2bc605b3dc7a5a4e2547018d7f18b49e519ece9067be6db04dea06356dea63bca0ef328ed312ab9270ed04dd6dffd3524d83ade23cb10051eb93281b83417e2cba965885e7ee012d9ee5b9d497cd1dc79996c3b301fd4279c8fef195adabc01808df994d148091ce14176df7831ca0b71969384050a16976a9e578f3cc941d84d436b920f6fd3daad140b65b8ae89e4ab9e2c810c94eb34bb13f7d67249579f1a01f071abcc17b9ed5966a8934981fbd758ec86272a97a5ce2f775b958104caff4d25d410dbbeafa51b9607fea23eb50795ace414795d11ba6618cff0899fd73081ea45552543c720c96d332a69e689381c45541fe8bea6880184167ad371fbcaf02a4d773ab4fcb1e9bfd8e794ce2aa5b8fdb100b46c07bfea1a1fbad8482559a57ee58cd558be3e2ddcfa09b8784efcbb41f907040ec3bc4c94b45cde233abbe553d8c1d63c95e0c255c1254a00e920c0a4390c7000b724c6824524ecaaab56665b799bfce546e0564342f9c3c6e60ec827d126c8bb9c6c2f735e6343c1e9e5bdfd80337af117b43bacc8a6f1caf2b943f2430c02db189892f57e103ba7119e5e280ae84bf0df40f68d7c7feca8a5a04b1cb50122e868aa96fe13c9186855897783a5db92f18469aaac677b177d19565b08521d3810e9094abb668d8cb919f20b6c6af73a38d8cd20b353e690160916bfb7c4124465371d102cbb003eb9ab98adc44184de1126ffb20de7b7899067b909fc8b1092a0c2e947725839c187ad71869e6c53c63dff202f839ff654baec3f4e607c24101e865f15d29b2bd21baea29231bebe0a411ef5adc219b024c236513dd741"
    );

    Wrapper wrapper;

    function setUp() public {
        bytes32 signer_hash = bytes32(TestValidSignerHash);
        wrapper = new Wrapper(signer_hash);
    }

    function loadPlonkInclusionFixture() public view returns (SphinxProofFixture memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/inclusion_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixture));
    }

    function loadPlonkEpochChangeFixture() public view returns (SphinxProofFixture memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/plonk_fixtures/epoch_change_fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SphinxProofFixture));
    }

    function testValidEpochChangeProofCore() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        SphinxVerifier core = new SphinxVerifier();
        uint256 gasCost = gasleft();
        core.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);
        require(gasCost - gasleft() < 300000, "Too big gas cost");
    }

    function testValidInclusionProofCore() public {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        SphinxVerifier core = new SphinxVerifier();
        uint256 gasCost = gasleft();
        core.verifyProof(fixture.vkey, fixture.publicValues, fixture.proof);
        require(gasCost - gasleft() < 300000, "Too big gas cost");
    }

    function testValidInclusionProofPlonk() public view {
        SphinxProofFixture memory fixture;
        fixture.vkey = bytes32(TestInclusionVkey);
        fixture.publicValues = TestInclusionPublicValues;
        fixture.proof = TestInclusionProof;

        uint256 gasCost = gasleft();
        wrapper.verifyInclusion(fixture);
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }

    function testValidEpochChangeProofPlonk() public {
        SphinxProofFixture memory fixture;
        fixture.vkey = bytes32(TestEpochChangeVkey);
        fixture.publicValues = TestEpochChangePublicValues;
        fixture.proof = TestEpochChangeProof;

        uint256 gasCost = gasleft();
        wrapper.verifyEpochChange(fixture);
        require(gasCost - gasleft() < 500000, "Too big gas cost");
    }

    // Negative tests with a fake proof
    function testFail_FakeProofInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        fixture.proof = fakeProof;
        wrapper.verifyInclusion(fixture);
    }

    function testFail_FakeProofEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakeProof = new bytes(fixture.proof.length);
        fixture.proof = fakeProof;
        wrapper.verifyEpochChange(fixture);
    }

    function testFail_FakePublicValuesInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length + 100);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyInclusion(fixture);
    }

    function testFail_FakePublicValuesEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        bytes memory fakePublicValues = new bytes(fixture.proof.length);
        fixture.publicValues = fakePublicValues;
        wrapper.verifyEpochChange(fixture);
    }

    // Negative tests with a wrong vk (currently failing, need to be enabled if porting v1.0.7-testnet contracts of SP1 to Sphinx)
    function testFail_WrongVkValuesInclusion() public view {
        SphinxProofFixture memory epochChangeFixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory inner = inclusionFixture;
        inner.vkey = epochChangeFixture.vkey;
        // taking vk from epoch change for proof / public values from inclusion
        wrapper.verifyInclusion(inner);
    }

    function testFail_WrongVkValuesEpochChange() public {
        SphinxProofFixture memory inclusionFixture = loadPlonkInclusionFixture();
        SphinxProofFixture memory epochChangefixture = loadPlonkEpochChangeFixture();
        SphinxProofFixture memory inner = epochChangefixture;
        inner.vkey = inclusionFixture.vkey;
        // taking vk from inclusion for proof / public values from epoch change
        wrapper.verifyEpochChange(inner);
    }

    function testFailInvalidSignerHashInclusion() public view {
        SphinxProofFixture memory fixture = loadPlonkInclusionFixture();
        // alter signer hash which is first 32 bytes
        fixture.publicValues[0] = 0xff;
        wrapper.verifyInclusion(fixture);
    }

    function testFailInvalidSignerHashEpochChange() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        // alter signer hash which is first 32 bytes
        fixture.publicValues[0] = 0xff;
        wrapper.verifyEpochChange(fixture);
    }

    function testEpochChangeSignerHashUpdate() public {
        SphinxProofFixture memory fixture = loadPlonkEpochChangeFixture();
        // use altered public values to make test pass
        fixture.publicValues = TestEpochChangePublicValues;
        require(wrapper.getSignerHash() == bytes32(TestValidSignerHash), "Unexpected value of signer hash during setup");
        wrapper.verifyEpochChange(fixture);
        require(wrapper.getSignerHash() == bytes32(TestUpdatedSignerHash), "Signer hash was not updated");
    }
}
