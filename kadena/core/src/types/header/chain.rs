// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::sha512::{hash_inner, hash_tagged_data};
use crate::crypto::hash::{HashValue, DIGEST_BYTES_LENGTH};
use crate::crypto::{Rational, U256, U256_BYTES_LENGTH};
use crate::merkle::{
    BLOCK_CREATION_TIME_TAG, BLOCK_HEIGHT_TAG, BLOCK_NONCE_TAG, BLOCK_WEIGHT_TAG,
    CHAINWEB_VERSION_TAG, CHAIN_ID_TAG, EPOCH_START_TIME_TAG, FEATURE_FLAGS_TAG, HASH_TARGET_TAG,
};
use crate::types::adjacent::{
    AdjacentParentRecord, AdjacentParentRecordRaw, ADJACENTS_RAW_BYTES_LENGTH,
    ADJACENT_PARENT_RAW_BYTES_LENGTH,
};
use crate::types::error::{TypesError, ValidationError};
use crate::types::graph::GRAPH_DEGREE;
use crate::types::utils::extract_fixed_bytes;
use crate::types::{
    BLOCK_DELAY, U16_BYTES_LENGTH, U32_BYTES_LENGTH, U64_BYTES_LENGTH, WINDOW_WIDTH,
};
use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use getset::Getters;

/// Size in bytes of a Kadena header represented as a base64 string
pub const RAW_HEADER_BYTES_LEN: usize = (RAW_HEADER_DECODED_BYTES_LENGTH * 4 + 2) / 3;

///  Size in bytes of a Kadena header represented as a byte array
pub const RAW_HEADER_DECODED_BYTES_LENGTH: usize = FLAGS_BYTES_LENGTH
    + TIME_BYTES_LENGTH
    + PARENT_BYTES_LENGTH
    + ADJACENTS_RAW_BYTES_LENGTH
    + TARGET_BYTES_LENGTH
    + PAYLOAD_BYTES_LENGTH
    + CHAIN_BYTES_LENGTH
    + WEIGHT_BYTES_LENGTH
    + HEIGHT_BYTES_LENGTH
    + VERSION_BYTES_LENGTH
    + EPOCH_START_BYTES_LENGTH
    + NONCE_BYTES_LENGTH
    + HASH_BYTES_LENGTH;

/// Size in bytes of the flags property of a Kadena header
pub const FLAGS_BYTES_LENGTH: usize = 8;

/// Size in bytes of the time property of a Kadena header
pub const TIME_BYTES_LENGTH: usize = 8;

/// Size in bytes of the parent property of a Kadena header
pub const PARENT_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;

/// Size in bytes of the target property of a Kadena header
pub const TARGET_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;

/// Size in bytes of the payload property of a Kadena header
pub const PAYLOAD_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;

/// Size in bytes of the chain property of a Kadena header
pub const CHAIN_BYTES_LENGTH: usize = 4;

/// Size in bytes of the weight property of a Kadena header
pub const WEIGHT_BYTES_LENGTH: usize = U256_BYTES_LENGTH;

/// Size in bytes of the height property of a Kadena header
pub const HEIGHT_BYTES_LENGTH: usize = U64_BYTES_LENGTH;

/// Size in bytes of the version property of a Kadena header
pub const VERSION_BYTES_LENGTH: usize = U32_BYTES_LENGTH;

/// Size in bytes of the epoch_start property of a Kadena header
pub const EPOCH_START_BYTES_LENGTH: usize = U64_BYTES_LENGTH;

/// Size in bytes of the nonce property of a Kadena header
pub const NONCE_BYTES_LENGTH: usize = U64_BYTES_LENGTH;

/// Size in bytes of the hash property of a Kadena header
pub const HASH_BYTES_LENGTH: usize = DIGEST_BYTES_LENGTH;

/// Representation of a Kadena header with its properties as bytes
/// arrays.
///
/// From [the`chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Block-Header-Binary-Encoding#blockheader-binary-format-for-chain-graphs-of-degree-three-without-hash).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct KadenaHeaderRaw {
    flags: [u8; FLAGS_BYTES_LENGTH],
    time: [u8; TIME_BYTES_LENGTH],
    parent: [u8; PARENT_BYTES_LENGTH],
    adjacents: [u8; ADJACENTS_RAW_BYTES_LENGTH],
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

impl Default for KadenaHeaderRaw {
    fn default() -> Self {
        Self {
            flags: [0; FLAGS_BYTES_LENGTH],
            time: [0; TIME_BYTES_LENGTH],
            parent: [0; PARENT_BYTES_LENGTH],
            adjacents: [0; ADJACENTS_RAW_BYTES_LENGTH],
            target: [0; TARGET_BYTES_LENGTH],
            payload: [0; PAYLOAD_BYTES_LENGTH],
            chain: [0; CHAIN_BYTES_LENGTH],
            weight: [0; WEIGHT_BYTES_LENGTH],
            height: [0; HEIGHT_BYTES_LENGTH],
            version: [0; VERSION_BYTES_LENGTH],
            epoch_start: [0; EPOCH_START_BYTES_LENGTH],
            nonce: [0; NONCE_BYTES_LENGTH],
            hash: [0; HASH_BYTES_LENGTH],
        }
    }
}

impl KadenaHeaderRaw {
    /// Creates a new `KadenaHeaderRaw` from a base64 encoded string bytes.
    ///
    /// # Arguments
    ///
    /// * `input` - A slice of bytes representing the base64 encoded string.
    ///
    /// # Returns
    ///
    /// A new `KadenaHeaderRaw` instance.
    pub fn from_base64(input: &[u8]) -> Result<Self, TypesError> {
        let decoded =
            URL_SAFE_NO_PAD
                .decode(input)
                .map_err(|err| TypesError::DeserializationError {
                    structure: "KadenaHeaderRaw".to_string(),
                    source: err.into(),
                })?;

        Self::from_bytes(&decoded)
    }

    /// Creates a new `KadenaHeaderRaw` from a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `input` - A slice of bytes representing the header.
    ///
    /// # Returns
    ///
    /// A new `KadenaHeaderRaw` instance.
    pub fn from_bytes(input: &[u8]) -> Result<Self, TypesError> {
        if input.len() != RAW_HEADER_DECODED_BYTES_LENGTH {
            return Err(TypesError::InvalidLength {
                structure: "KadenaHeaderRaw".to_string(),
                expected: RAW_HEADER_DECODED_BYTES_LENGTH,
                actual: input.len(),
            });
        }

        let cursor = 0;

        let (cursor, flags) =
            extract_fixed_bytes::<FLAGS_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, time) =
            extract_fixed_bytes::<TIME_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, parent) =
            extract_fixed_bytes::<PARENT_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, adjacents) =
            extract_fixed_bytes::<ADJACENTS_RAW_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, target) =
            extract_fixed_bytes::<TARGET_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, payload) =
            extract_fixed_bytes::<PAYLOAD_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, chain) =
            extract_fixed_bytes::<CHAIN_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, weight) =
            extract_fixed_bytes::<WEIGHT_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, height) =
            extract_fixed_bytes::<HEIGHT_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, version) =
            extract_fixed_bytes::<VERSION_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, epoch_start) =
            extract_fixed_bytes::<EPOCH_START_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (cursor, nonce) =
            extract_fixed_bytes::<NONCE_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;
        let (_, hash) = extract_fixed_bytes::<HASH_BYTES_LENGTH>("KadenaHeaderRaw", input, cursor)?;

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

    /// Encodes the `KadenaHeaderRaw` instance as a base64 string bytes.
    ///
    /// # Returns
    ///
    /// The bytes of the Kadena header encoded as a base64. .
    pub fn to_base64(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        URL_SAFE_NO_PAD.encode(&bytes).into_bytes()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.flags);
        serialized.extend_from_slice(&self.time);
        serialized.extend_from_slice(&self.parent);
        serialized.extend_from_slice(&self.adjacents);
        serialized.extend_from_slice(&self.target);
        serialized.extend_from_slice(&self.payload);
        serialized.extend_from_slice(&self.chain);
        serialized.extend_from_slice(&self.weight);
        serialized.extend_from_slice(&self.height);
        serialized.extend_from_slice(&self.version);
        serialized.extend_from_slice(&self.epoch_start);
        serialized.extend_from_slice(&self.nonce);
        serialized.extend_from_slice(&self.hash);

        serialized
    }

    /// Computes the root hash of the header.
    ///
    /// # Returns
    ///
    /// The root hash of the header.
    ///
    /// # Notes
    ///
    /// When the  chain graph degree changes along with the [`crate::types::graph::TWENTY_CHAIN_GRAPH_DEGREE`]
    /// constant this method should be updated.
    pub fn header_root(&self) -> Result<HashValue, CryptoError> {
        let mut adjacent_hashes: Vec<[u8; 32]> = Vec::with_capacity(GRAPH_DEGREE);
        for i in 0..GRAPH_DEGREE {
            let start =
                U16_BYTES_LENGTH + i * ADJACENT_PARENT_RAW_BYTES_LENGTH + CHAIN_BYTES_LENGTH;
            let end = start + DIGEST_BYTES_LENGTH;
            adjacent_hashes.push(
                self.adjacents[start..end]
                    .try_into()
                    .expect("Should be able to convert adjacent hash to fixed length array"),
            );
        }

        // Bottom leaves
        let hashes = vec![
            hash_tagged_data(FEATURE_FLAGS_TAG, self.flags())?,
            hash_tagged_data(BLOCK_CREATION_TIME_TAG, self.time())?,
            HashValue::new(*self.parent()),
            hash_tagged_data(HASH_TARGET_TAG, self.target())?,
            HashValue::new(*self.payload()),
            hash_tagged_data(CHAIN_ID_TAG, self.chain())?,
            hash_tagged_data(BLOCK_WEIGHT_TAG, self.weight())?,
            hash_tagged_data(BLOCK_HEIGHT_TAG, self.height())?,
            hash_tagged_data(CHAINWEB_VERSION_TAG, self.version())?,
            hash_tagged_data(EPOCH_START_TIME_TAG, self.epoch_start())?,
            hash_tagged_data(BLOCK_NONCE_TAG, self.nonce())?,
            HashValue::new(adjacent_hashes[0]),
        ];
        // Hash bottom leaves pairs
        let mut intermediate_hashes = hashes
            .chunks(2)
            .map(|pair| hash_inner(pair[0].as_ref(), pair[1].as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        // Include additional adjacent nodes at the correct level
        intermediate_hashes.push(HashValue::new(adjacent_hashes[1]));
        intermediate_hashes.push(HashValue::new(adjacent_hashes[2]));

        // Hash pairs of intermediate nodes until only one hash remains (the root)
        while intermediate_hashes.len() > 1 {
            intermediate_hashes = intermediate_hashes
                .chunks(2)
                .map(|pair| hash_inner(pair[0].as_ref(), pair[1].as_ref()))
                .collect::<Result<Vec<_>, _>>()?;
        }

        // The last remaining hash is the root
        Ok(intermediate_hashes[0])
    }

    /// Computes the work produced to mine the block. The work produced
    /// should be inferior or equal to the target of the block.
    ///
    /// # Returns
    ///
    /// The work produced to mine the block.
    pub fn produced_work(&self) -> Result<U256, ValidationError> {
        let target = U256::from_little_endian(&self.target);
        let hash = U256::from_little_endian(
            &self
                .pow_hash()
                .map(|hash| hash.to_vec())
                .map_err(|err| ValidationError::HashError { source: err.into() })?,
        );

        if hash <= target {
            Ok(target)
        } else {
            Err(ValidationError::TargetNotMet {
                target: target.to_string(),
                hash: hash.to_string(),
            })
        }
    }

    /// Computes the proof of work hash of the header.
    ///
    /// # Returns
    ///
    /// The proof of work hash of the header.
    pub fn pow_hash(&self) -> Result<HashValue, CryptoError> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.flags);
        serialized.extend_from_slice(&self.time);
        serialized.extend_from_slice(&self.parent);
        serialized.extend_from_slice(&self.adjacents);
        serialized.extend_from_slice(&self.target);
        serialized.extend_from_slice(&self.payload);
        serialized.extend_from_slice(&self.chain);
        serialized.extend_from_slice(&self.weight);
        serialized.extend_from_slice(&self.height);
        serialized.extend_from_slice(&self.version);
        serialized.extend_from_slice(&self.epoch_start);
        serialized.extend_from_slice(&self.nonce);

        crate::crypto::hash::blake2::hash_data(&serialized)
    }

    /// Computes the proof of work hash of the header.
    ///
    /// # Returns
    ///
    /// The proof of work hash of the header.
    pub const fn decoded_height(&self) -> u64 {
        u64::from_le_bytes(self.height)
    }

    /// Calculate the adjusted target for a given chain on a new Epoch.
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent header of the current header.
    ///
    /// # Returns
    ///
    /// The adjusted target for the new epoch.
    ///
    /// # Notes
    ///
    /// Based on [the Chainweb Wiki](https://github.com/kadena-io/chainweb-node/wiki/Block-Difficulty).
    pub fn target_adjustment(&self, parent: &Self) -> Result<Rational, ValidationError> {
        if u64::from_le_bytes(self.height) % WINDOW_WIDTH != 0 {
            return Err(ValidationError::InvalidEpochStartHeight {
                height: u64::from_le_bytes(self.height),
                epoch_length: WINDOW_WIDTH,
            });
        }

        if self.parent() != parent.hash() {
            return Err(ValidationError::InvalidParentHash {
                computed: HashValue::new(*self.parent()),
                stored: HashValue::new(*parent.hash()),
            });
        }

        // Previous epoch target
        let parent_target = Rational::from(U256::from_little_endian(parent.target()));
        // Previous epoch start time, timestamp in microseconds
        let parent_epoch_start = Rational::from(u64::from_le_bytes(parent.epoch_start));
        // Previous epoch end time, timestamp in microseconds
        let parent_epoch_end = Rational::from(u64::from_le_bytes(parent.time));

        // Calculate new target
        let actual_duration = parent_epoch_end - parent_epoch_start;
        let target_duration = Rational::from(WINDOW_WIDTH) * Rational::from(BLOCK_DELAY);
        let quotient = (actual_duration / target_duration) * parent_target;

        Ok(Rational::from(quotient.ceil().min(U256::max_value())))
    }

    /// Set the parent for the Kadena header.
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent hash to set.
    ///
    /// # Notes
    ///
    /// This method is only for testing purposes.
    #[cfg(feature = "kadena")]
    pub fn set_parent(&mut self, parent: HashValue) {
        self.parent = *parent.as_ref();
    }

    /// Set the hash value for the Kadena header.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash value to set.
    ///
    /// # Notes
    ///
    /// This method is only for testing purposes.
    #[cfg(feature = "kadena")]
    pub fn set_hash(&mut self, hash: HashValue) {
        self.hash = *hash.as_ref();
    }

    /// Set the height for the Kadena header.
    ///
    /// # Arguments
    ///
    /// * `height` - The height to set.
    ///
    /// # Notes
    ///
    /// This method is only for testing purposes.
    #[cfg(feature = "kadena")]
    pub fn set_height(&mut self, height: u64) {
        self.height = height.to_le_bytes();
    }
}

/// Representation of a Kadena header with its properties as Rust types.
#[derive(Debug, Getters)]
#[getset(get = "pub")]
#[allow(dead_code)]
struct KadenaHeader {
    flags: [u8; 8], // All 0s, for future usage
    time: DateTime<Utc>,
    parent: U256,
    adjacents: AdjacentParentRecord,
    target: U256,
    payload: HashValue,
    chain: [u8; 4],
    weight: U256,
    height: u64,
    version: u32,
    epoch_start: DateTime<Utc>,
    nonce: [u8; 8],
    hash: HashValue,
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
            AdjacentParentRecord::from(AdjacentParentRecordRaw::from_bytes(&raw.adjacents));

        let target = U256::from_little_endian(&raw.target);
        let payload = HashValue::new(raw.payload);
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
        let hash = HashValue::new(raw.hash);

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

/// A compact representation of a Kadena header.
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct CompactHeaderRaw {
    time: [u8; 8],
    payload: [u8; 32],
    nonce: [u8; 8],
}

impl CompactHeaderRaw {
    /// Creates a new `CompactHeaderRaw` from a base64 encoded string bytes.
    ///
    /// # Arguments
    ///
    /// * `input` - A slice of bytes representing the base64 encoded string.
    ///
    /// # Returns
    ///
    /// A new `CompactHeaderRaw` instance.
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

#[cfg(all(test, feature = "kadena"))]
mod test {
    use crate::crypto::hash::HashValue;
    use crate::crypto::U256;
    use crate::test_utils::{RAW_HEADER, RAW_HEADER_POW_HASH_HEX};
    use crate::types::header::chain::{KadenaHeader, KadenaHeaderRaw, RAW_HEADER_BYTES_LEN};
    use std::process::Stdio;
    use uint::hex;

    #[test]
    fn test_decode_binary_no_panic() {
        let header_raw = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();

        let encoded_header_raw = header_raw.to_base64();

        assert_eq!(RAW_HEADER.to_vec(), encoded_header_raw);

        let _ = KadenaHeader::try_from(header_raw).unwrap();
    }

    #[test]
    fn test_bytes_conversion_header_raw() {
        let header_raw = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();
        let bytes = header_raw.to_bytes();
        let deserialized = KadenaHeaderRaw::from_bytes(&bytes).unwrap();
        assert_eq!(header_raw, deserialized);
    }

    #[test]
    fn test_compute_pow_hash() {
        let header_raw = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();
        let actual =
            U256::from_little_endian(&header_raw.pow_hash().map(|hash| hash.to_vec()).unwrap());
        let expected = U256::from_big_endian(&hex::decode(RAW_HEADER_POW_HASH_HEX).unwrap());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_multiple_header_root_computing() {
        use crate::test_utils::TESTNET_CHAIN_3_HEADERS_URL;
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
                assert_eq!(actual, HashValue::new(*expected));
            }
        });
    }
}
