// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Wrapper, SphinxProofFixture} from "../src/Wrapper.sol";

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
        abi.encodePacked(hex"00e54e06bcdc2c59766110a06babf99bb8bc180c2de0faf0bb03785cbaf432fe");
    bytes private TestInclusionPublicValues = abi.encodePacked(
        hex"205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ec13ac3f4a611fb8075f1d1baa53150bb357cd8567332fd69ea65609be7dca63b2030000000000000044fa02feb400a383b1824df6198c7e30cbf60a21838efa46fedf35f760fdf25839d1a3ec2b5d09aee31c1c0c380eef28744673ea3ab7e9d065baccc8d1874ca1"
    );
    bytes private TestInclusionProof = abi.encodePacked(
        hex"21caa4127c78e9ee40d1a5b0a01cea79dc9ed732ed3211cf89ef585050ecb2d3266f185fe50aa2c67253e104df3f2dc68b0907d32a7be4d7da4978e52b85ce800365ed142ea620fa98e598fb5b9682edd06e38c88e7919adbd6e18f555f32bb20c4a0b3a9abef679d120dc72ea08441bfc02f697764efff66a88e19cbd1266e606a524e663e5a8074a120ddf6119257fa69964daa136f053d437306e505742890e42b74e9c29f90cb03d5e2ce808945d99ca24296357c78970af36b363ff8cb0220ae7511a4d86fc6da91e01a0e20886feb7d29f9bfc69dd75c364fdf76afad92e5c8ddad4124b38c057d0d4a4d9bbf73679c1666bb96d0ca582fb23b92e0e5a1f1514da6bccfaa20e10d8759a567f972baf7f823582c21ce96ab6d53f2096350fd90de8582ab8e2c3e13503ba07d4c1d1f8ed0ecbe4a1a60e4c6130cd556e460c19d06660599ef32cd49cbd5b3e510dbfa575ed2b234ba32a6fe68023453e6616e684870545a1e67267bfa5782d363bdc931146fbd85645c8d38cd1904f253b2cb235736d988e7c1ba10c0d9e6e82fdfb797930458619510d3c825b19bb3cb72f053dc03850cbe37142626b790de357cb4fd0093ca8ce84828e5f02f8090be70689d0180d27284361399a74854b538c096f39f66f900baa3ee9be20f5eed25f21fee7c58b57165a28dd267041b8ebe5057141ab3f5372d9de456ae73d8991cc06ba7d1c1dfbb6e0a68b1c4b102b1571845eec6c9e30f75cf41d6ca6afa64f4300833f04760a3003d49147bcfa946ac86113a5625e451d0e5ab0efb05e7cbbc302ae84247d3952c764f7a85105750002204eec6c02ae1519b927d8f78a7201940d3e189078a15dcb6d0b5f492ee5219ec14ea202fcd7c79322fcb42ad80c347e0871325dc47996067ead745c25d058ddba63f5faa2a02433ce1aa043585dd6391a20b5b957c5d87e22920c93660ee62d6feff33c872f421f0737aa8823758c160806d559986c26819fb218f2028f7ed38557562f0b597ce1c4690bfb1767fe262ea03745ce2ea58206e8e4b7995e76eb07bdff8e31d28d53057248a986c1d8480cb8d50c1e7de2846346914c70c47bcf78f386d09ed2a6c8d5e5d3e681ca8db305a16abfa98410aa18af6de36f2c3a551a8babb61868f13b2fe1dfdc219b9ffa1c93163144ab0328f045596150915f79301111c393f98c51074fc271b2adb676"
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
