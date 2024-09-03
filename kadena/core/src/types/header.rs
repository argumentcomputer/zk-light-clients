use crate::crypto::hash::{hash_data, hash_inner, hash_root};
use crate::crypto::U256;
use crate::types::adjacent::{AdjacentParentRecord, AdjacentParentRecordRaw};
use crate::types::{
    BLOCK_CREATION_TIME_TAG, BLOCK_HEIGHT_TAG, BLOCK_NONCE_TAG, BLOCK_WEIGHT_TAG,
    CHAINWEB_VERSION_TAG, CHAIN_ID_TAG, EPOCH_START_TIME_TAG, FEATURE_FLAGS_TAG, HASH_TARGET_TAG,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use getset::Getters;
use std::convert::TryInto;

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

    pub fn header_root(&self) -> Vec<u8> {
        let header = KadenaHeader::from(self.clone());
        // TODO can directly extract
        let adjacents = header.adjacents().hashes();

        // Bottom leaves
        let hashes = vec![
            hash_data(FEATURE_FLAGS_TAG, self.flags()),
            hash_data(BLOCK_CREATION_TIME_TAG, self.time()),
            hash_root(self.parent()),
            hash_data(HASH_TARGET_TAG, self.target()),
            hash_root(self.payload()),
            hash_data(CHAIN_ID_TAG, self.chain()),
            hash_data(BLOCK_WEIGHT_TAG, self.weight()),
            hash_data(BLOCK_HEIGHT_TAG, self.height()),
            hash_data(CHAINWEB_VERSION_TAG, self.version()),
            hash_data(EPOCH_START_TIME_TAG, self.epoch_start()),
            hash_data(BLOCK_NONCE_TAG, self.nonce()),
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

impl From<KadenaHeaderRaw> for KadenaHeader {
    fn from(raw: KadenaHeaderRaw) -> Self {
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

#[cfg(test)]
mod test {
    use crate::types::header::{KadenaHeader, KadenaHeaderRaw};
    use std::process::Stdio;

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
    const TESTNET_CHAIN_3_HEADERS_URL: &str =
        "https://api.testnet.chainweb.com/chainweb/0.0/testnet04/chain/3/header/";

    #[test]
    fn test_decode_binary_no_panic() {
        let header_raw = KadenaHeaderRaw::from_base64(RAW_HEADER);
        let _ = KadenaHeader::from(header_raw);
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
            let header_str = header_str.replace([',', '[', ']', '\"'], "");
            let header_bytes = header_str.as_bytes();
            // skip "garbage" in headers
            if header_bytes.len() == RAW_HEADER_BYTES_LEN {
                let parsed_header = KadenaHeaderRaw::from_base64(header_bytes);
                let actual = parsed_header.header_root();
                let expected = parsed_header.hash();
                assert_eq!(actual, expected.to_vec());
            }
        });
    }
}
