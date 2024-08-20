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
        abi.encodePacked(hex"008f0133dc5a02eb31ac769e9e3a2f34da1af34c963bf3ee9a058982a2978cc9");
    bytes private TestEpochChangePublicValues = abi.encodePacked(
        hex"205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ecc071f215064bfe6f1c24295135199ce6f6dec2974115fad50989e666915453ad"
    );
    bytes private TestEpochChangeProof = abi.encodePacked(
        hex"a85584422a848d6615d731b6b12d755d14514e776f2509176f2e9678efeffac647a8543c3037c967c8bee22ece9629e8b265955143933a9b2811b2cfc12298c7ba99a7de0ddfa29e6d69c14da6477e1557a5c1d507a26481b2d28ed768837dfd0420797d00a1d144d1d30135eda50df9d6904fbba8e8c32052394583c4ae8f68895a431829cc83ced958a7b614d24eedcf523c7413e7ec234095e808524a21c948ffb7bc0838c2ae4ddb6c1b50f462dd42c22e049a9cf43364c9af1f55ab4883d5f30afd0e641effc953868bace766a9ed67d0d5f1c0276faf40ba02951b5149aaa5d0161f55dbbb9a7af707c9eaef2a21abd24312c3b6d17352fbe5df7f293267d456cf1a3c6bacdf1ab788ca65fb93acbe94db3cd14d44c406f4acc07d47fbb8c58b6729ee8a8bc74db938c89833cbb75265ad45aa9d001ea758d60077f8e61e45c4ff0e8d46d952778944e8ddd387f90114bc90f8d6bd89f05e4e48121fc8ac09560e19b54fb817a93efb37006a9f1b6146016648c7ea5a2fbad5b5c13e7d6b7064220891f0a6d8e87bd4b2142ff1ebb909f300cc4d078734ee2340460cf29c75cf9212cc7b6f473d48d2c3f61ca548826e296493c56676df31716268349e5cf466d92d7c8d5cf166a96c0f69b188a258acfb350eedbb5bd030225580cbf98587102e0683afba98713fb55f1d2462ff389816bb4c2a4d776b8e64e4eb35d9c6d3e3950ef973d79f55b5fdf573d85c7445cf0a44195302ae185260f6b68fef401fc7f6159f060c1fb9c20802914780d88f6d5501dbb419178a2c5c249c7f7594d89cfe0895a67a085dba1d29c758f3363e0961b8ae2975a4cbeab0e89e9cf329fd9c7925157f49f0e05082f15c0fdd2cc1fbdddb890061b11f6df5155727654588ba0f060fdec748ed5ea822f1dec725fb0a44bebd5a313f68dde008698b6d1b3365752702e16fecdc672d66e00256db9fc0de58ba9e3602b757b4c99418051204bb9b1b7b7e318b750f95b7ac2504f4cdf1c400855a8b99ea37b9553b11bac180ca2308775113f4a9d86aa580ca68a9bbec4e8555253680a9c6ff5817a4e1d5ae2d5e28cddc2cd44f8cff7cc80202b66bcac0861f15afa0c4bf5356951218b39cf75f09202cc1b745bc8eec6aeb082caa8095e121a85196c84b7c3c6a4e0395b0cc452901f62988dfb27e0fb55710eaee7d1a8ded34d5da344a05dfe5f25521f7b9e2"
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
