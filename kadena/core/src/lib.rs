use sha2::{Digest, Sha512_256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use getset::Getters;
use uint::construct_uint;

construct_uint! {
    pub struct U256(4);
}

// Tag values can be found here:
// https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function
const CHAIN_ID_TAG: u16 = 0x0002;
const BLOCK_HEIGHT_TAG: u16 = 0x0003;
const BLOCK_WEIGHT_TAG: u16 = 0x0004;
const FEATURE_FLAGS_TAG: u16 = 0x0006;
const BLOCK_CREATION_TIME_TAG: u16 = 0x0007;
const CHAINWEB_VERSION_TAG: u16 = 0x0008;
const HASH_TARGET_TAG: u16 = 0x0011;
const EPOCH_START_TIME_TAG: u16 = 0x0019;
const BLOCK_NONCE_TAG: u16 = 0x0020;

// Hash functions for Merkle tree nodes
// cf. https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#merke-log-trees
pub type ChainwebHash = Sha512_256;

pub fn tag_bytes(tag: u16) -> [u8; 2] {
    tag.to_be_bytes()
}

pub fn hash_data(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x0];
    ChainwebHash::digest([x, &tag_bytes(tag), bytes].concat()).to_vec()
}

pub fn hash_root(bytes: &[u8; 32]) -> Vec<u8> {
    bytes.to_vec()
}

pub fn hash_inner(left: &[u8], right: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x1];
    ChainwebHash::digest([x, left, right].concat()).to_vec()
}

pub fn header_root(kadena_raw: &KadenaHeaderRaw) -> Vec<u8> {
    let header = KadenaHeader::from_raw(&kadena_raw.clone());
    let adjacents = header.adjacents().hashes();

    // Bottom leaves
    let hashes = vec![
        hash_data(FEATURE_FLAGS_TAG, kadena_raw.flags()),
        hash_data(BLOCK_CREATION_TIME_TAG, kadena_raw.time()),
        hash_root(kadena_raw.parent()),
        hash_data(HASH_TARGET_TAG, kadena_raw.target()),
        hash_root(kadena_raw.payload()),
        hash_data(CHAIN_ID_TAG, kadena_raw.chain()),
        hash_data(BLOCK_WEIGHT_TAG, kadena_raw.weight()),
        hash_data(BLOCK_HEIGHT_TAG, kadena_raw.height()),
        hash_data(CHAINWEB_VERSION_TAG, kadena_raw.version()),
        hash_data(EPOCH_START_TIME_TAG, kadena_raw.epoch_start()),
        hash_data(BLOCK_NONCE_TAG, kadena_raw.nonce()),
        hash_root(&adjacents[0]),
    ];
    // Hash bottom leaves pairs
    let mut intermediate_hashes = hashes
        .chunks(2)
        .map(|pair| hash_inner(&pair[0], &pair[1]))
        .collect::<Vec<_>>();

    // Include additional adjacent nodes at the correct level
    intermediate_hashes.push(hash_root(&adjacents[1]));
    intermediate_hashes.push(hash_root(&adjacents[2]));

    // Hash pairs of intermediate nodes until only one hash remains (the root)
    while intermediate_hashes.len() > 1 {
        intermediate_hashes = intermediate_hashes
            .chunks(2)
            .map(|pair| hash_inner(&pair[0], &pair[1]))
            .collect();
    }

    // The last remaining hash is the root
    intermediate_hashes[0].clone()
}

pub struct AdjacentParentRaw {
    chain: [u8; 4],
    hash: [u8; 32],
}

impl AdjacentParentRaw {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let chain: [u8; 4] = bytes[0..4].try_into().unwrap();
        let hash: [u8; 32] = bytes[4..36].try_into().unwrap();

        Self { chain, hash }
    }
}

#[derive(Debug)]
pub struct AdjacentParent {
    chain: u32,
    hash: [u8; 32],
}

impl AdjacentParent {
    pub fn from_raw(raw: &AdjacentParentRaw) -> Self {
        let chain = u32::from_le_bytes(raw.chain);
        let hash = raw.hash;

        Self { chain, hash }
    }
}

pub struct AdjacentParentRecordRaw {
    length: [u8; 2],
    adjacents: [u8; 108],
}

impl AdjacentParentRecordRaw {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let length: [u8; 2] = bytes[0..2].try_into().unwrap();
        let adjacents: [u8; 108] = bytes[2..110].try_into().unwrap();

        Self { length, adjacents }
    }
}

#[repr(align(1))]
#[derive(Debug)]
#[allow(dead_code)]
pub struct AdjacentParentRecord {
    length: u16,
    adjacents: [AdjacentParent; 3],
}

impl AdjacentParentRecord {
    pub fn from_raw(raw: &AdjacentParentRecordRaw) -> Self {
        let length = u16::from_le_bytes(raw.length);
        let mut adjacents = [
            AdjacentParent::from_raw(&AdjacentParentRaw::from_bytes(
                raw.adjacents[0..36].try_into().unwrap(),
            )),
            AdjacentParent::from_raw(&AdjacentParentRaw::from_bytes(
                raw.adjacents[36..72].try_into().unwrap(),
            )),
            AdjacentParent::from_raw(&AdjacentParentRaw::from_bytes(
                raw.adjacents[72..108].try_into().unwrap(),
            )),
        ];

        // just in case
        adjacents.sort_unstable_by_key(|v| v.chain);

        Self { length, adjacents }
    }

    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.adjacents.iter().map(|a| a.hash).collect()
    }
}

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct KadenaHeaderRaw {
    flags: [u8; 8],
    time: [u8; 8],
    parent: [u8; 32],
    adjacents: [u8; 110],
    target: [u8; 32],
    payload: [u8; 32],
    chain: [u8; 4],
    weight: [u8; 32],
    height: [u8; 8],
    version: [u8; 4],
    epoch_start: [u8; 8],
    nonce: [u8; 8],
    hash: [u8; 32],
}

#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct KadenaHeader {
    flags: [u8; 8], // All 0s, for future usage
    time: DateTime<Utc>,
    parent: U256,
    adjacents: AdjacentParentRecord,
    target: U256,
    payload: [u8; 32],
    chain: [u8; 4],
    weight: U256,
    height: u64,
    version: u32,
    epoch_start: DateTime<Utc>,
    nonce: [u8; 8],
    hash: [u8; 32],
}

impl KadenaHeader {
    pub fn from_raw(raw: &KadenaHeaderRaw) -> Self {
        let flags = raw.flags;
        let creation_time =
            DateTime::from_timestamp_micros(u64::from_le_bytes(raw.time) as i64).unwrap();
        let parent = U256::from_little_endian(&raw.parent);
        let adjacents =
            AdjacentParentRecord::from_raw(&AdjacentParentRecordRaw::from_bytes(&raw.adjacents));

        let target = U256::from_little_endian(&raw.target);
        let payload = raw.payload;
        let chain = raw.chain;
        let weight = U256::from_little_endian(&raw.weight);
        let height = u64::from_le_bytes(raw.height);
        let version = u32::from_le_bytes(raw.version);
        let epoch_start =
            DateTime::from_timestamp_micros(u64::from_le_bytes(raw.epoch_start) as i64).unwrap();
        let nonce = raw.nonce;
        let hash = raw.hash;

        Self {
            flags,
            time: creation_time,
            parent,
            adjacents,
            target,
            payload,
            chain,
            weight,
            height,
            version,
            epoch_start,
            nonce,
            hash,
        }
    }
}

impl KadenaHeaderRaw {
    pub fn from_base64(input: &[u8]) -> Self {
        let decoded = URL_SAFE_NO_PAD.decode(input).unwrap();

        let flags: [u8; 8] = decoded[0..8].try_into().unwrap();
        let time: [u8; 8] = decoded[8..16].try_into().unwrap();
        let parent: [u8; 32] = decoded[16..48].try_into().unwrap();
        let adjacents: [u8; 110] = decoded[48..158].try_into().unwrap();
        let target: [u8; 32] = decoded[158..190].try_into().unwrap();
        let payload: [u8; 32] = decoded[190..222].try_into().unwrap();
        let chain: [u8; 4] = decoded[222..226].try_into().unwrap();
        let weight: [u8; 32] = decoded[226..258].try_into().unwrap();
        let height: [u8; 8] = decoded[258..266].try_into().unwrap();
        let version: [u8; 4] = decoded[266..270].try_into().unwrap();
        let epoch_start: [u8; 8] = decoded[270..278].try_into().unwrap();
        let nonce: [u8; 8] = decoded[278..286].try_into().unwrap();
        let hash: [u8; 32] = decoded[286..318].try_into().unwrap();

        Self {
            flags,
            time,
            parent,
            adjacents,
            target,
            payload,
            chain,
            weight,
            height,
            version,
            epoch_start,
            nonce,
            hash,
        }
    }
}


#[cfg(test)]
mod test {
    use std::process::Stdio;
    use base64::Engine;
    use crate::{
        KadenaHeader, KadenaHeaderRaw, header_root, tag_bytes, ChainwebHash, BLOCK_CREATION_TIME_TAG, BLOCK_HEIGHT_TAG,
        BLOCK_NONCE_TAG, BLOCK_WEIGHT_TAG, CHAINWEB_VERSION_TAG, CHAIN_ID_TAG,
        EPOCH_START_TIME_TAG, FEATURE_FLAGS_TAG, HASH_TARGET_TAG,
    };

    // this binary data comes from this block header: https://explorer.chainweb.com/testnet/chain/0/block/PjTIbGWK6GnJosMRvBeN2Yoyue9zU2twuWCSYQ1IRRg
    // Extracted using the p2p REST API:
    // export NODE=us1.testnet.chainweb.com
    // export CHAINWEB_VERSION=testnet04
    // export CHAIN_ID=0
    // export BLOCKHEADER_HASH=PjTIbGWK6GnJosMRvBeN2Yoyue9zU2twuWCSYQ1IRRg=
    // export HEADER_ENCODING=''
    // curl -sk "https://${NODE}/chainweb/0.0/${CHAINWEB_VERSION}/chain/${CHAIN_ID}/header/${BLOCKHEADER_HASH}" ${HEADER_ENCODING}
    const RAW_HEADER: &[u8; RAW_HEADER_BYTES_LEN] = b"AAAAAAAAAAB97UtijQ4GABZadGj_lZHt2_fPGA0latJzV5-A68ZxHHj5vuSqaitWAwAFAAAAuIdT1f1Ljy2RW4pfv_qQZT701v9NiUO78l_ISWa5WE8KAAAAtgbgjwjxNIlyNxzVJFCZj3MSd-cC4tHEwPP4AMkndQYPAAAAQqZj-Xbeb0flE-pPUzZHnKIff0omUW3EHWk1pETh17Dt0Z6VjZnWIy6fsZz20SslSPE0ar6qTbHKG97AigIAAK-C-MGqrNxklX1UaYDYY7Ghvz3XNrv1XdHUyWktBmIpAAAAAFMcLVUmJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXRk8AAAAAAAHAAAAC6UQSI0OBgDOgg0AAAAAAD40yGxliuhpyaLDEbwXjdmKMrnvc1NrcLlgkmENSEUY";
    const RAW_HEADER_BYTES_LEN: usize = 424;

    // Some other valid block headers
    //const RAW_HEADER: &[u8; RAW_HEADER_BYTES_LEN] = b"AAAAAAAAAAACmFEpXKIFAFqnBc1TShDFkkFBmVKO-5iQg3VYbZXoHAHW5G8s1hGtAwAAAAAALg0UzRaXrSRnI1VrG6QC5K4zKSHmZRc7_YijkChipsMBAAAAiVAs8q7BjIn9Ku9bD3hgeXKAA5JAsREj2bZ11ULbeUwIAAAAvcOCfWo3JMHAG8aZvJRSlIaOhazIVhPxeg-NoTCd5g5Z5Kdd_FDWRq0DKTVnMm70lx3SBXzZ471ng0AergQAADq5MUlAkWvb09X2oPM6CJKP3gg4Zr7BoAOSFjtnKyvXAwAAAB-VZ0MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZwEAAAAAAAAHAAAAZ8U9WVuiBQBbTBQAAAAAAK_JUGU5QA2xe-dxVWyoWscrxSHj7lRrO8LGhDTf5ciX";
    //const RAW_HEADER: &[u8; RAW_HEADER_BYTES_LEN] = b"AAAAAAAAAADagen7WaIFAASBaVOSlhojqQjImJ0F2PR258lozvJLjkLfXfsEIjPCAwAAAAAAHHEJ8CfvcweMTfvSMBYlXLWv0v25Mt-4bK3RUi_L6lsBAAAAi0pTBul2AUh0jWNPs2LXCdc_sgEyFK01O_bmHgDwkWAIAAAAYzOtui7Ns_-SQp472GrIlRUmIl9UsDagsuZ-Xuzf_L3__________________________________________4dF0GK2zmpsHFv5NYbuvc0pyhXfXwxxJRM0uvq8InFUAwAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAACH1lqeSNBQAAAAAAAAAAAJhcOUndKMtEn5_aPlk_LbLgU-vK_gpvrf14eFWrgEFW";
    const TESTNET_CHAIN_3_HEADERS_URL: &str = "https://api.testnet.chainweb.com/chainweb/0.0/testnet04/chain/3/header/";

    /*
    #[tokio::test]
    async fn test_fetch_block_header() {
        pub async fn query_raw_header(client: &reqwest::Client) -> KadenaHeaderRaw {
            // Get Header
            let response_header = client
                .get("https://api.testnet.chainweb.com/chainweb/0.0/testnet04/chain/0/header/PjTIbGWK6GnJosMRvBeN2Yoyue9zU2twuWCSYQ1IRRg=")
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            KadenaHeaderRaw::from_base64(&response_header.to_vec()[1..response_header.len() - 1])
        }

        let client = reqwest::Client::new();

        let kadena_raw = query_raw_header(&client).await;

        let root = header_root(&kadena_raw);

        assert_eq!(root, kadena_raw.hash());
    }*/

    #[test]
    fn test_merkle_log_lib() {
        use merkle_log::tree::{MerkleHash, MerkleLogEntry, MerkleTree};
        use sha2::digest::Output;

        let kadena_raw = KadenaHeaderRaw::from_base64(RAW_HEADER);

        fn mk_root_entry(hash: &[u8]) -> MerkleLogEntry<ChainwebHash> {
            let r: Output<ChainwebHash> = Output::<ChainwebHash>::clone_from_slice(hash);
            MerkleLogEntry::TreeLeaf(MerkleHash(r))
        }

        fn mk_data_entry(tag: u16, data: &[u8]) -> MerkleLogEntry<ChainwebHash> {
            MerkleLogEntry::DataLeaf([&tag_bytes(tag), data].concat())
        }

        let header = KadenaHeader::from_raw(&kadena_raw.clone());
        let adjacents = header.adjacents().hashes();

        let entries = [
            mk_data_entry(FEATURE_FLAGS_TAG, kadena_raw.flags()),
            mk_data_entry(BLOCK_CREATION_TIME_TAG, kadena_raw.time()),
            mk_root_entry(kadena_raw.parent()),
            mk_data_entry(HASH_TARGET_TAG, kadena_raw.target()),
            mk_root_entry(kadena_raw.payload()),
            mk_data_entry(CHAIN_ID_TAG, kadena_raw.chain()),
            mk_data_entry(BLOCK_WEIGHT_TAG, kadena_raw.weight()),
            mk_data_entry(BLOCK_HEIGHT_TAG, kadena_raw.height()),
            mk_data_entry(CHAINWEB_VERSION_TAG, kadena_raw.version()),
            mk_data_entry(EPOCH_START_TIME_TAG, kadena_raw.epoch_start()),
            mk_data_entry(BLOCK_NONCE_TAG, kadena_raw.nonce()),
            mk_root_entry(&adjacents[0]),
            mk_root_entry(&adjacents[1]),
            mk_root_entry(&adjacents[2]),
        ];
        let tree = MerkleTree::<ChainwebHash>::new(&entries);

        let root = &header_root(&kadena_raw);

        assert_eq!(tree.root().0.as_slice(), root);
    }

    #[test]
    fn test_decode_binary_no_panic() {
        let header_raw = KadenaHeaderRaw::from_base64(RAW_HEADER);
        KadenaHeader::from_raw(&header_raw);
    }

    #[test]
    fn test_multiple_header_root_computing() {
        use std::process::Command;

        let curl = Command::new("curl")
            .arg("-s")
            .arg(TESTNET_CHAIN_3_HEADERS_URL)
            .stdout(Stdio::piped())
            .spawn()
            .expect("curl failure");

        let jq = Command::new("jq")
            .arg("-r")
            .arg(".items")
            .stdin(Stdio::from(curl.stdout.unwrap()))
            .stdout(Stdio::piped())
            .spawn()
            .expect("jq failure");

        let output = jq.wait_with_output().unwrap();
        let output = String::from_utf8_lossy(&output.stdout);
        let raw_headers = output.split_whitespace();
        raw_headers.for_each(|header_str| {
            let header_str = header_str.replace(&[',', '[', ']', '\"'], "");
            let header_bytes = header_str.as_bytes();
            // skip "garbage" in headers
            if header_bytes.len() == RAW_HEADER_BYTES_LEN {
                let parsed_header = KadenaHeaderRaw::from_base64(header_bytes);
                let actual = header_root(&parsed_header);
                let expected = parsed_header.hash();
                assert_eq!(actual, expected);
            }
        });
    }
}
