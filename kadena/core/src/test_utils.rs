// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::hash::HashValue;
use crate::merkle::spv::Spv;
use crate::types::header::chain::RAW_HEADER_BYTES_LEN;
use crate::types::header::layer::ChainwebLayerHeader;
use getset::Getters;
use std::fs;
use std::path::PathBuf;

// this binary data comes from this block header: https://explorer.chainweb.com/testnet/chain/0/block/PjTIbGWK6GnJosMRvBeN2Yoyue9zU2twuWCSYQ1IRRg
// Extracted using the p2p REST API:
// export NODE=api.chainweb.com
// export CHAINWEB_VERSION=mainnet01
// export CHAIN_ID=0
// export LIMIT=1
// export HEIGHT=5099342
// export HEADER_ENCODING=''
// curl -sk "https://${NODE}/chainweb/0.0/${CHAINWEB_VERSION}/chain/${CHAIN_ID}/header?limit=${LIMIT}&minheight=${HEIGHT}" ${HEADER_ENCODING}
pub const RAW_HEADER: &[u8; RAW_HEADER_BYTES_LEN] = b"AAAAAAAAAADD1nMoSCEGADwKaIUvrCBSw_x2E9gX8A6rfivaaLn1THmW84IVvdo0AwAFAAAA6ZwPwQh0J3kWxTtIHblGP-_lhfv6O93V5Z9X0MsAQxsKAAAAnzoFM2164175njvXT-WtFkI_EosVHYwQxCFBlsF3rzgPAAAAEACJMSvkDii6F6dO-_XPuKMMARIWp8zknQrNBVxRsjZidblKf3wbSh4GAAJhfP1BSX3rTDvx24QQAAAAAAAAAFd1EK_a_MHBiCdaexBxLz6cPvFtRYnF2ouOGtl9rB6NAAAAAKQEL9M9aOtZf2kBAAAAAAAAAAAAAAAAAAAAAAAAAAAATs9NAAAAAAAFAAAABjGCuEchBgADABULZ3D1rgPVKrDUtdRd5tLvtefzWK7MktQWIaH8OIm5WFPQ-cnv";
pub const RAW_HEADER_POW_HASH_HEX: &[u8; 64] =
    b"00000000000000039633411e726c4e458f380cb662430ef4bca0f676060985c6";
pub const TESTNET_CHAIN_3_HEADERS_URL: &str =
    "https://api.testnet.chainweb.com/chainweb/0.0/testnet04/chain/3/header/";

pub const COMPACT_HEADER_PATH: &str = "../test-assets/compact.json";
pub const CHAINWEB_LAYER_HEADERS_PATH: &str = "../test-assets/kadena_layer_headers.json";
pub const EPOCH_CHANGE_CHAINWEB_LAYER_HEADERS_PATH: &str =
    "../test-assets/epoch_change_kadena_layer_headers.json";
pub const SPV_PATH: &str = "../test-assets/spv.json";

pub fn get_compact_headers_bytes() -> Vec<u8> {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let test_asset_path = root_path.join(COMPACT_HEADER_PATH);

    fs::read(test_asset_path).unwrap()
}

pub fn get_layer_block_headers() -> Vec<ChainwebLayerHeader> {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let test_asset_path = root_path.join(CHAINWEB_LAYER_HEADERS_PATH);

    let bytes: Vec<u8> = serde_json::from_slice(&fs::read(test_asset_path).unwrap()).unwrap();

    ChainwebLayerHeader::deserialize_list(&bytes).unwrap()
}

pub fn get_epoch_change_layer_block_headers() -> Vec<ChainwebLayerHeader> {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let test_asset_path = root_path.join(EPOCH_CHANGE_CHAINWEB_LAYER_HEADERS_PATH);

    let bytes: Vec<u8> = serde_json::from_slice(&fs::read(test_asset_path).unwrap()).unwrap();

    ChainwebLayerHeader::deserialize_list(&bytes).unwrap()
}

pub fn get_spv() -> Spv {
    let root_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let test_asset_path = root_path.join(SPV_PATH);

    let bytes: Vec<u8> = serde_json::from_slice(&fs::read(test_asset_path).unwrap()).unwrap();

    Spv::from_bytes(&bytes).unwrap()
}

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct TestAssets {
    layer_headers: Vec<ChainwebLayerHeader>,
    spv: Spv,
    expected_root: HashValue,
}

pub fn get_test_assets() -> TestAssets {
    let layer_heads = get_layer_block_headers();
    let spv = get_spv();
    let expected_root = HashValue::new(
        *layer_heads[layer_heads.len() / 2]
            .chain_headers()
            .first()
            .unwrap()
            .hash(),
    );

    TestAssets {
        layer_headers: layer_heads,
        spv,
        expected_root,
    }
}

pub fn random_hash() -> HashValue {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut arr = [0u8; 32];
    rng.fill(&mut arr); // Fill the array with random bytes
    HashValue::new(arr)
}

pub fn random_string(len: usize) -> String {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char) // Generate random alphanumeric chars
        .collect()
}
