use crate::types::storage::GetProofResponse;
use ethereum_lc_core::merkle::storage_proofs::EIP1186Proof;
use ethereum_lc_core::types::bootstrap::Bootstrap;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::{FinalityUpdate, Update};
use std::fs;
use std::path::PathBuf;

pub struct CommitteeChangeTestAssets {
    pub store: LightClientStore,
    pub update: Update,
    pub update_new_period: Update,
}

pub fn generate_committee_change_test_assets() -> CommitteeChangeTestAssets {
    // Instantiate bootstrap data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/committee-change/LightClientBootstrapDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();
    let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate Update data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/committee-change/LightClientUpdateDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let update = Update::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate new period Update data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/committee-change/LightClientUpdateNewPeriodDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let update_new_period = Update::from_ssz_bytes(&test_bytes).unwrap();

    // Initialize the LightClientStore
    let checkpoint = "0xefb4338d596b9d335b2da176dc85ee97469fc80c7e2d35b9b9c1558b4602077a";
    let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

    CommitteeChangeTestAssets {
        store,
        update,
        update_new_period,
    }
}

pub struct InclusionTestAssets {
    pub store: LightClientStore,
    pub finality_update: FinalityUpdate,
    pub eip1186_proof: EIP1186Proof,
}

pub fn generate_inclusion_test_assets() -> InclusionTestAssets {
    // Instantiate bootstrap data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/LightClientBootstrapDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate Update data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/LightClientUpdateDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let update = Update::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate finality update data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/LightClientFinalityUpdateDeneb.ssz");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let finality_update = FinalityUpdate::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate EIP1186 proof data
    let test_asset_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-assets/inclusion/base-data/EthGetProof.json");

    let test_bytes = fs::read(test_asset_path).unwrap();

    let ethers_eip1186_proof: GetProofResponse = serde_json::from_slice(&test_bytes).unwrap();

    // Initialize the LightClientStore
    let checkpoint = "0xf783c545d2dd90cee6c4cb92a9324323ef397f6ec85e1a3d61c48cf6cfc979e2";
    let trusted_block_root = hex::decode(checkpoint.strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

    store.process_light_client_update(&update).unwrap();

    InclusionTestAssets {
        store,
        finality_update,
        eip1186_proof: EIP1186Proof::try_from(ethers_eip1186_proof.result().clone()).unwrap(),
    }
}
