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
        abi.encodePacked(hex"0049db69bb4f4f06cddfb1aa47738ec568589ecb72cce157064391dab5bf749b");
    bytes private TestInclusionPublicValues = abi.encodePacked(
        hex"205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ec4921987f359fc1f9482c493bf7378db9fca188451b56fe3007ec8c0105d7c2a9020202020202020202020202020202020202020202020202020202020202020244fa02feb400a383b1824df6198c7e30cbf60a21838efa46fedf35f760fdf25839d1a3ec2b5d09aee31c1c0c380eef28744673ea3ab7e9d065baccc8d1874ca1"
    );
    bytes private TestInclusionProof = abi.encodePacked(
        hex"19766fbbd87b34a85a37d4553e46adbdefe3d1633ef632c4b3a3dd1cfffb88c623c58ea58729fba3e2d139921d026f80c35c352cfada675f68caa33f5fadafae2c90327aa4b63e76fb8e3cfdfa4dd77e1f7a739bff6c2056378be4a8c2a298850972c1299d56ca6500d1590c074f50c5508c7123fc79b594aa2752b3417821242c094a1df1918b7e42b1d63ef7ce475a2212a24b6c0e4b364a50fd9f259348192930efcd1ec69a0bf4c57d0152bfb77c06493960940735109948865814b508f32acb9dac228c3708b66e17894b65749e0093c6d1bc3efce4dab0e10efd0cb6a00609f7c720e1298aea5fcc0d54ae838c592079b6243e19856a86e619a7217c371b42efdf4853f99e80dbccabb4a6c15404360b606ad684787e207472096b34f81b36e6214b2ecb98a1897f701096aa0cea17ebe12cc01274b78f64dbb385e7e12cfa34313e39c5d7749d78c55b5aa86e1b91eb129d83b63915cb3651772a20f81f2f24cbbe4259192b106742d272409c701a0e16f39e9a1895aa69038f51c34709b18c22ef8af33aa72aac809e4bcf028da2f19506973bf3ada9345e3d760d4a2d40cd9354fbb88b5cb2185b3a0438c9450b822c6809b7029dedcf0a4101c4701d5cfd4cb0c5ca526f2b7a3f8eca95473e666cb8a7db1f54e5c5765c49e4c5132e2b17ab8ebe6262ca821de5e00fcf24bdf06b3a93856fb7933835a18b849cda1d32d128b4c05318b9c08c08b39777bbd9e66d89aae1ff6b675a07fea86a8dd71f9a3c8db30779f58c79a2ab32e7f423fd4896d235c4df610a13792693911b351c240dbf6a1c87cdb5287d5eee80491b1fe322e54e4cb596612573d2a63689c2278a84e391193bc3a6ddab48f522b819d067e77a7f0df1ca4538e401cfec706c0cc2ab73e04805b7ea000bd647a67d4d701de3fc7812c2b5aa22854d9a7d39212742d4b51e4122308e6249b1601b5098ec2926480fca1abb4f7e57c66a846ee203898982369346dd5cdd8d16ed498a663a0ed8c07e0aa1064358363bf282a0d70fdd7328163b0624eeb6981ebe70e9a0c4afffbb09d896b068f8b54e7e4a0d62081e6124a36ec5a174ced54f63e2b75d96d7438395f8ee86195e35b619a29a341b1e44cb366a1d505a7c1b6579e1f0963631df08410ddf88fc44a5540c7296b6273ac8f322f54a991abcd4e9a4a8b174888bfd23b0748bcd5a31d48c1aaa93dc"
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
