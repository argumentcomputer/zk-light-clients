// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::hash::{hash_data, hash_inner, hash_root, DIGEST_BYTES_LENGTH};
use crate::crypto::{U256, U256_BYTES_LENGTH};
use crate::types::adjacent::{AdjacentParentRecord, AdjacentParentRecordRaw};
use crate::types::error::TypesError;
use crate::types::utils::extract_fixed_bytes;
use crate::types::{
    BLOCK_CREATION_TIME_TAG, BLOCK_HEIGHT_TAG, BLOCK_NONCE_TAG, BLOCK_WEIGHT_TAG,
    CHAINWEB_VERSION_TAG, CHAIN_ID_TAG, EPOCH_START_TIME_TAG, FEATURE_FLAGS_TAG, HASH_TARGET_TAG,
    U32_BYTES_LENGTH, U64_BYTES_LENGTH,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use getset::Getters;
use std::convert::TryInto;

pub const RAW_HEADER_BYTES_LEN: usize = 424;
pub const RAW_HEADER_DECODED_BYTES_LENGTH: usize = FLAGS_BYTES_LENGTH
    + TIME_BYTES_LENGTH
    + PARENT_BYTES_LENGTH
    + ADJACENTS_BYTES_LENGTH
    + TARGET_BYTES_LENGTH
    + PAYLOAD_BYTES_LENGTH
    + CHAIN_BYTES_LENGTH
    + WEIGHT_BYTES_LENGTH
    + HEIGHT_BYTES_LENGTH
    + VERSION_BYTES_LENGTH
    + EPOCH_START_BYTES_LENGTH
    + NONCE_BYTES_LENGTH
    + HASH_BYTES_LENGTH;

pub const FLAGS_BYTES_LENGTH: usize = 8;
pub const TIME_BYTES_LENGTH: usize = 8;
pub const PARENT_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;
pub const ADJACENTS_BYTES_LENGTH: usize = 110;
pub const TARGET_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;
pub const PAYLOAD_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;
pub const CHAIN_BYTES_LENGTH: usize = 4;
pub const WEIGHT_BYTES_LENGTH: usize = U256_BYTES_LENGTH;
pub const HEIGHT_BYTES_LENGTH: usize = U64_BYTES_LENGTH;
pub const VERSION_BYTES_LENGTH: usize = U32_BYTES_LENGTH;
pub const EPOCH_START_BYTES_LENGTH: usize = U64_BYTES_LENGTH;
pub const NONCE_BYTES_LENGTH: usize = U64_BYTES_LENGTH;
pub const HASH_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct KadenaHeaderRaw {
    flags: [u8; FLAGS_BYTES_LENGTH],
    time: [u8; TIME_BYTES_LENGTH],
    parent: [u8; PARENT_BYTES_LENGTH],
    adjacents: [u8; ADJACENTS_BYTES_LENGTH],
    target: [u8; TARGET_BYTES_LENGTH],
    payload: [u8; PAYLOAD_BYTES_LENGTH],
    chain: [u8; CHAIN_BYTES_LENGTH],
    weight: [u8; WEIGHT_BYTES_LENGTH],
    height: [u8; HEIGHT_BYTES_LENGTH],
    version: [u8; VERSION_BYTES_LENGTH],
    epoch_start: [u8; EPOCH_START_BYTES_LENGTH],
    nonce: [u8; NONCE_BYTES_LENGTH],
    hash: [u8; HASH_BYTES_LENGTH],
}

impl KadenaHeaderRaw {
    pub fn from_base64(input: &[u8]) -> Result<Self, TypesError> {
        let decoded =
            URL_SAFE_NO_PAD
                .decode(input)
                .map_err(|err| TypesError::DeserializationError {
                    structure: "KadenaHeaderRaw".to_string(),
                    source: err.into(),
                })?;

        if decoded.len() != RAW_HEADER_DECODED_BYTES_LENGTH {
            return Err(TypesError::InvalidLength {
                structure: "KadenaHeaderRaw".to_string(),
                expected: RAW_HEADER_DECODED_BYTES_LENGTH,
                actual: decoded.len(),
            });
        }

        let cursor = 0;

        let (cursor, flags) =
            extract_fixed_bytes::<FLAGS_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, time) =
            extract_fixed_bytes::<TIME_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, parent) =
            extract_fixed_bytes::<PARENT_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, adjacents) =
            extract_fixed_bytes::<ADJACENTS_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, target) =
            extract_fixed_bytes::<TARGET_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, payload) =
            extract_fixed_bytes::<PAYLOAD_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, chain) =
            extract_fixed_bytes::<CHAIN_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, weight) =
            extract_fixed_bytes::<WEIGHT_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, height) =
            extract_fixed_bytes::<HEIGHT_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, version) =
            extract_fixed_bytes::<VERSION_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, epoch_start) =
            extract_fixed_bytes::<EPOCH_START_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (cursor, nonce) =
            extract_fixed_bytes::<NONCE_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;
        let (_, hash) =
            extract_fixed_bytes::<HASH_BYTES_LENGTH>("KadenaHeaderRaw", &decoded, cursor)?;

        Ok(Self {
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
        })
    }

    pub fn to_base64(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.flags);
        encoded.extend_from_slice(&self.time);
        encoded.extend_from_slice(&self.parent);
        encoded.extend_from_slice(&self.adjacents);
        encoded.extend_from_slice(&self.target);
        encoded.extend_from_slice(&self.payload);
        encoded.extend_from_slice(&self.chain);
        encoded.extend_from_slice(&self.weight);
        encoded.extend_from_slice(&self.height);
        encoded.extend_from_slice(&self.version);
        encoded.extend_from_slice(&self.epoch_start);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.hash);
        URL_SAFE_NO_PAD.encode(&encoded).into_bytes()
    }

    pub fn header_root(&self) -> Result<Vec<u8>, TypesError> {
        let adjacent_hashes: Vec<[u8; 32]> = vec![
            self.adjacents[6..6 + DIGEST_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to convert adjacent hash to fixed length array"),
            self.adjacents[42..42 + DIGEST_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to convert adjacent hash to fixed length array"),
            self.adjacents[78..78 + DIGEST_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to convert adjacent hash to fixed length array"),
        ];

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
            hash_root(&adjacent_hashes[0]),
        ];
        // Hash bottom leaves pairs
        let mut intermediate_hashes = hashes
            .chunks(2)
            .map(|pair| hash_inner(&pair[0], &pair[1]))
            .collect::<Vec<_>>();

        // Include additional adjacent nodes at the correct level
        intermediate_hashes.push(hash_root(&adjacent_hashes[1]));
        intermediate_hashes.push(hash_root(&adjacent_hashes[2]));

        // Hash pairs of intermediate nodes until only one hash remains (the root)
        while intermediate_hashes.len() > 1 {
            intermediate_hashes = intermediate_hashes
                .chunks(2)
                .map(|pair| hash_inner(&pair[0], &pair[1]))
                .collect();
        }

        // The last remaining hash is the root
        Ok(intermediate_hashes[0].clone())
    }
}

#[derive(Debug, Getters)]
#[getset(get = "pub")]
#[allow(dead_code)]
struct KadenaHeader {
    flags: [u8; 8], // All 0s, for future usage
    time: DateTime<Utc>,
    parent: U256,
    adjacents: AdjacentParentRecord,
    target: U256,
    payload: [u8; DIGEST_BYTES_LENGTH],
    chain: [u8; 4],
    weight: U256,
    height: u64,
    version: u32,
    epoch_start: DateTime<Utc>,
    nonce: [u8; 8],
    hash: [u8; DIGEST_BYTES_LENGTH],
}

impl TryFrom<KadenaHeaderRaw> for KadenaHeader {
    type Error = TypesError;

    fn try_from(raw: KadenaHeaderRaw) -> Result<Self, Self::Error> {
        let flags = raw.flags;
        let creation_time = DateTime::from_timestamp_micros(u64::from_le_bytes(raw.time) as i64)
            .ok_or_else(|| TypesError::ConversionError {
                source: "Could not convert time bytes to DateTime".into(),
                from: "KadenaHeaderRaw".into(),
                to: "KadenaHeader".into(),
            })?;
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
            DateTime::from_timestamp_micros(u64::from_le_bytes(raw.epoch_start) as i64)
                .ok_or_else(|| TypesError::ConversionError {
                    source: "Could not convert epoch_start bytes to DateTime".into(),
                    from: "KadenaHeaderRaw".into(),
                    to: "KadenaHeader".into(),
                })?;
        let nonce = raw.nonce;
        let hash = raw.hash;

        Ok(Self {
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
        })
    }
}

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct CompactHeaderRaw {
    time: [u8; 8],
    payload: [u8; 32],
    nonce: [u8; 8],
}

impl CompactHeaderRaw {
    pub fn from_base64(input: &[u8]) -> Result<Self, TypesError> {
        let decoded =
            URL_SAFE_NO_PAD
                .decode(input)
                .map_err(|err| TypesError::DeserializationError {
                    structure: "CompactHeaderRaw".to_string(),
                    source: err.into(),
                })?;

        if decoded.len() != TIME_BYTES_LENGTH + PAYLOAD_BYTES_LENGTH + NONCE_BYTES_LENGTH {
            return Err(TypesError::InvalidLength {
                structure: "CompactHeaderRaw".to_string(),
                expected: TIME_BYTES_LENGTH + PAYLOAD_BYTES_LENGTH + NONCE_BYTES_LENGTH,
                actual: decoded.len(),
            });
        }

        let cursor = 0;

        let (cursor, time) =
            extract_fixed_bytes::<TIME_BYTES_LENGTH>("CompactHeaderRaw", &decoded, cursor)?;
        let (cursor, payload) =
            extract_fixed_bytes::<PAYLOAD_BYTES_LENGTH>("CompactHeaderRaw", &decoded, cursor)?;
        let (_, nonce) =
            extract_fixed_bytes::<NONCE_BYTES_LENGTH>("CompactHeaderRaw", &decoded, cursor)?;

        Ok(Self {
            time,
            payload,
            nonce,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::types::header::{KadenaHeader, KadenaHeaderRaw, RAW_HEADER_BYTES_LEN};
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
    const TESTNET_CHAIN_3_HEADERS_URL: &str =
        "https://api.testnet.chainweb.com/chainweb/0.0/testnet04/chain/3/header/";

    #[test]
    fn test_decode_binary_no_panic() {
        let header_raw = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();

        let encoded_header_raw = header_raw.to_base64();

        assert_eq!(RAW_HEADER.to_vec(), encoded_header_raw);

        let _ = KadenaHeader::try_from(header_raw).unwrap();
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
                let parsed_header = KadenaHeaderRaw::from_base64(header_bytes).unwrap();
                let actual = parsed_header.header_root().unwrap();
                let expected = parsed_header.hash();
                assert_eq!(actual, expected.to_vec());
            }
        });
    }
}
