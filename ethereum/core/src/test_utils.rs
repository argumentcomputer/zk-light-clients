use crate::merkle::storage_proofs::EIP1186Proof;
use crate::types::bootstrap::Bootstrap;
use crate::types::store::LightClientStore;
use crate::types::update::{FinalityUpdate, Update};
use ethers_core::types::EIP1186ProofResponse;
use getset::Getters;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

const INCLUSION_BOOTSTRAP_DENEB_PATH: &str =
    "../test-assets/inclusion/LightClientBootstrapDeneb.ssz";
const INCLUSION_UPDATE_DENEB_PATH: &str = "../test-assets/inclusion/LightClientUpdateDeneb.ssz";
const INCLUSION_FINALITY_UPDATE_PATH: &str =
    "../test-assets/inclusion/LightClientFinalityUpdateDeneb.ssz";
const ETH_GET_PROOF: &str = "../test-assets/inclusion/base-data/EthGetProof.json";

const COMMITTEE_CHANGE_BOOTSTRAP_DENEB_PATH: &str =
    "../test-assets/committee-change/LightClientBootstrapDeneb.ssz";
const COMMITTEE_CHANGE_UPDATE_DENEB_PATH: &str =
    "../test-assets/committee-change/LightClientUpdateDeneb.ssz";
const COMMITTEE_CHANGE_UPDATE_NEW_PERIOD: &str =
    "../test-assets/committee-change/LightClientUpdateNewPeriodDeneb.ssz";

const INCLUSION_CHECKPOINT: &str =
    "0xf783c545d2dd90cee6c4cb92a9324323ef397f6ec85e1a3d61c48cf6cfc979e2";
const COMMITTEE_CHANGE_CHECKPOINT: &str =
    "0xefb4338d596b9d335b2da176dc85ee97469fc80c7e2d35b9b9c1558b4602077a";

#[derive(Getters)]
#[getset(get = "pub")]
pub struct CommitteeChangeTestAssets {
    pub store: LightClientStore,
    pub update: Update,
    pub update_new_period: Update,
}

pub fn generate_committee_change_test_assets() -> CommitteeChangeTestAssets {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Instantiate bootstrap data
    let test_asset_path = root_path.join(COMMITTEE_CHANGE_BOOTSTRAP_DENEB_PATH);

    let test_bytes = fs::read(test_asset_path).unwrap();
    let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate Update data
    let test_asset_path = root_path.join(COMMITTEE_CHANGE_UPDATE_DENEB_PATH);

    let test_bytes = fs::read(test_asset_path).unwrap();

    let update = Update::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate new period Update data
    let test_asset_path = root_path.join(COMMITTEE_CHANGE_UPDATE_NEW_PERIOD);

    let test_bytes = fs::read(test_asset_path).unwrap();

    let update_new_period = Update::from_ssz_bytes(&test_bytes).unwrap();

    // Initialize the LightClientStore
    let trusted_block_root = hex::decode(COMMITTEE_CHANGE_CHECKPOINT.strip_prefix("0x").unwrap())
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

#[derive(Getters)]
#[getset(get = "pub")]
pub struct InclusionTestAssets {
    store: LightClientStore,
    finality_update: FinalityUpdate,
    eip1186_proof: EIP1186Proof,
}

pub fn generate_inclusion_test_assets() -> InclusionTestAssets {
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Instantiate bootstrap data
    let test_asset_path = root_dir.join(INCLUSION_BOOTSTRAP_DENEB_PATH);

    let test_bytes = fs::read(test_asset_path).unwrap();

    let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate Update data
    let test_asset_path = root_dir.join(INCLUSION_UPDATE_DENEB_PATH);

    let test_bytes = fs::read(test_asset_path).unwrap();

    let update = Update::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate finality update data
    let test_asset_path = root_dir.join(INCLUSION_FINALITY_UPDATE_PATH);

    let test_bytes = fs::read(test_asset_path).unwrap();

    let finality_update = FinalityUpdate::from_ssz_bytes(&test_bytes).unwrap();

    // Instantiate EIP1186 proof data
    let test_asset_path = root_dir.join(ETH_GET_PROOF);

    let test_bytes = fs::read(test_asset_path).unwrap();

    let ethers_eip1186_proof: Value = serde_json::from_slice(&test_bytes).unwrap();

    let call_res = ethers_eip1186_proof
        .get("result")
        .expect("Ethers EIP1186 proof result not found");
    let ethers_eip1186_proof: EIP1186ProofResponse =
        serde_json::from_value(call_res.clone()).unwrap();

    // Initialize the LightClientStore
    let trusted_block_root = hex::decode(INCLUSION_CHECKPOINT.strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let mut store = LightClientStore::initialize(trusted_block_root, &bootstrap).unwrap();

    store.process_light_client_update(&update).unwrap();

    InclusionTestAssets {
        store,
        finality_update,
        eip1186_proof: EIP1186Proof::try_from(ethers_eip1186_proof).unwrap(),
    }
}
