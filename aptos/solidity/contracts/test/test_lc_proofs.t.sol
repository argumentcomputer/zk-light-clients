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
        abi.encodePacked(hex"0072b60af92b70d22263ea319349c33af704baf7a4bc11cbac41265e34e8381e");
    bytes private TestEpochChangePublicValues = abi.encodePacked(
        hex"205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ecc071f215064bfe6f1c24295135199ce6f6dec2974115fad50989e666915453ad"
    );
    bytes private TestEpochChangeProof = abi.encodePacked(
        hex"7f8918df0a945ea9a1da51e5eb0bea9e42b90d55f49b28a82d74c4335a84c91fb0c42524058aa4379105a1f201802d290e09e8579dd72699dd3eb054eac4737fd1acc4872a6315109bfc320556788079c1e1fa4bd34c8552dc1ca6b31b7fe4bb4c9fa0f01e2ee0af2e8d3f49f9b14d8b4cb0b44870b453e563bb4111bd826d4be11d4a2519b5a792435f1653c5046eb784702d5962c311b36658824949fcd3952dd57ea905e742c08afb817d551ea34e17d1b8db4aeca7d3b22967f90d2ec626bd57a48d122a0eb57d4c2d011a0664e4f506b84b5a8033e13817089668270c7268f4a3ca1af5b814c3a102a2c0851995fa52541ccc33b1cf6aafffb309a6c88a60e1fb3024ab1f2eaf5d28522e47ffd7e1268bf13c99905c43f83af42141be86aeb99ea404e103a38ebca1786141976e848a0a194fff60faed6c4a0b6d2bee603ae15a5c00bc610e3f66c8fc4b8d0c1e078a425deda25f5b152398d6740d2e50fbca05bc0b71ec953a1239a2a73689709ec165bb3c91e8276be35660b4c7c738eb15074c2c515981e938c98034a7a8a3fd399fcdec38656213892ea63c6bc1e5c8f512de0378f078c5938e00c493e2ff1ca8052eab62226ebdb1d65eef9413097b42618f02c5efbdb9b61d266c7c718d06cfaad509810d29144840526e9b4b85b286e5182e6ca883036a88f1c830e3812545daf5d7577705fa93eae807888505872081dd1c8fc8765fc4812a37320e98b3428b84abf656b87a35b5075d11b944309187ef29531e0dac9a930cd1ccb7900fa4e28177097ad6c3386cf3d3d7323a23ba6a4e13d3419209d68855306616b00d146a6f94937561ae92413e2b5a9defe25616011f827c2723a3c204d8a7223cae5220c01178b4e5c7e1a32fe8b8e89f9389e9090fc99d68b179cb13d7fd1de6aae6f12aac8fbf217086e5276c5024cd4188a95208bcd1fdca180606a3612a1e59c6ddf90008f8c056e095558ab233b2bb16e2582fc2bdea4e2191e016436600afa2e7d5f7c82e0efdeceaadf8d001ee754d94c71a02a97a1c4f9a714ac2169600cc7dc21620471b855bddbda0c8ec0d058afc0c2e5a498c68c2c4e80ee64f33eeaa0805070fc84e7b29dcdf01eb73ec83d61ed401778c005b659b770338ea725778cf9ab18cc5f2152f813b4cd81dca86ff67f529e2074723fb36563c63ed2be904dbdff1d99b5a812c5349a16b989d1c2e7810"
    );

    // valid inclusion fixture for testing purposes
    bytes private TestInclusionVkey =
        abi.encodePacked(hex"00952ef4ec4d22d6bcc5ecae9bfdf5b445d9597a9aa9c7675c53d6bfb1b1b840");
    bytes private TestInclusionPublicValues = abi.encodePacked(
        hex"205829098a4c0273312e8bc4fdbde28fc12abdc540c88bdd9abeef0a85d706ec3f03a5ae69c235b1dacf4bc86a4edf0c6fd3ebb2fe7d57154d64fed46472fd6e020202020202020202020202020202020202020202020202020202020202020244fa02feb400a383b1824df6198c7e30cbf60a21838efa46fedf35f760fdf25839d1a3ec2b5d09aee31c1c0c380eef28744673ea3ab7e9d065baccc8d1874ca1"
    );
    bytes private TestInclusionProof = abi.encodePacked(
        hex"7f8918df04f27b9dce4273954636b7c4bcae34f39f467dd85832e61b6553c02a3c67ff5c233fae19455b1e22211e261f9d0bcd7341d0a85c50007a6c104db7dda189089015b1f6ac4c844b026f136db1826b39ac80e789be1c558b1db109522f6eb6476922ca4c0bc16e021e6a193c3bd5215cfce060adbdd835ef7c11d0c8f926778b91067191207cfe343a19fc70e02598774456c6212921dc2aae9fa80a81a7c416172127f798a98af732a165b16f369afa41ea2b1c7b446c9a063f8966680a972fa010537e56fef644ed11f887bb91349326ea5318b552f10afeccaa493254c26a4d27a442c7d3e269f8adde970f83de71ce7145ec4a68dfb2f72c82080fd93f086b18368674a0c7fd32ae20ab26d1eaa68ed20465314603d9fb984d2b8809a4f95a006237c75ec9feccac71bfb34980e04b8e6e0487200d0ef4d758f1cafc03b0330d9026a040234e57a8e6c86e25e262a3d3cafb6947062505ed6804c5e604ce532dd1169c36c7e8629ab026ed9074c7eee87ed2b2639a4448eaf2747b49fba584100734e10d0458db473c9a50625e59aaae6373117fb923aff4224f57c587e8fb0e835235211b02d4ee4fc4055ae997525ebb3820a820669c7ac3d7c62092ccef035e056a768d1b0c375abd20054e8482029b721c501d22933d6f008214e3823520450b12164c9214a248a564ac74c403168ede6794314780b777ddbba660ca1e1f1f02933555387dc0f2e2fbd40b140103437ed1801ca60728f8ff8a2d11fa5c2fd92708d7ee3ab93800bf01846aa596748ecd10c03fd1dfef58a7774c3af9542f93a40249c77eba59fd8f872f835866e1dc5f7520a23874546c4f79f0f1fc0d1f0644b0150373494a05d2a7628c3380f41d955298cbc545029a40f7e37817a721287113fd2b5927623cc3f9846ace2b3b17702c16c06c54ba223f9c646177ba08971c60c6a5e786eeae2ceb4f012e591d9a3f9761d541050edea10cc6f37e6a1b9ad2bb906b11a72522b70b3efbeea56713c8f407c57be4ea367a45546cf1221417d34b72f09a842d8bb0504803a42cd127db238ed75837eb3f233ec2b5aac513f4f5afc2a3abd83add10185dbcf3f8700fa75cfeb7ba667e1607fd1fc6fe6e0f4cedf4967a936339c2656e7e7ae934f79a187e33b49faf766e1eb05625a44027b444b11049594e8ab0acb4d3df6200772a351dd35984d5c4bb84d94975a847"
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
