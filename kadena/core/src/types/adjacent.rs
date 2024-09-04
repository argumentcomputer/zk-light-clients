// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::hash::DIGEST_BYTES_LENGTH;
use crate::types::header::CHAIN_BYTES_LENGTH;
use crate::types::U16_BYTES_LENGTH;

pub const ADJACENTS_RAW_BYTES_LENGTH: usize = 110;
pub const ADJACENT_RECORD_RAW_BYTES_LENGTH: usize = 108;
pub const ADJACENT_RECORD_PER_BLOCK: usize = 3;

pub struct AdjacentParentRaw {
    chain: [u8; CHAIN_BYTES_LENGTH],
    hash: [u8; DIGEST_BYTES_LENGTH],
}

impl AdjacentParentRaw {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let chain: [u8; 4] = bytes[0..CHAIN_BYTES_LENGTH].try_into().unwrap();
        let hash: [u8; 32] = bytes[CHAIN_BYTES_LENGTH..CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH]
            .try_into()
            .unwrap();

        Self { chain, hash }
    }
}

#[derive(Debug)]
pub struct AdjacentParent {
    chain: u32,
    hash: [u8; DIGEST_BYTES_LENGTH],
}

impl From<&AdjacentParentRaw> for AdjacentParent {
    fn from(raw: &AdjacentParentRaw) -> Self {
        let chain = u32::from_le_bytes(raw.chain);
        let hash = raw.hash;

        Self { chain, hash }
    }
}

pub struct AdjacentParentRecordRaw {
    length: [u8; U16_BYTES_LENGTH],
    adjacents: [u8; ADJACENT_RECORD_RAW_BYTES_LENGTH],
}

impl AdjacentParentRecordRaw {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let length: [u8; U16_BYTES_LENGTH] = bytes[0..U16_BYTES_LENGTH].try_into().unwrap();
        let adjacents: [u8; ADJACENT_RECORD_RAW_BYTES_LENGTH] = bytes
            [U16_BYTES_LENGTH..ADJACENTS_RAW_BYTES_LENGTH]
            .try_into()
            .unwrap();

        Self { length, adjacents }
    }
}

impl From<AdjacentParent> for AdjacentParentRaw {
    fn from(adjacent: AdjacentParent) -> Self {
        let chain = adjacent.chain.to_le_bytes();
        let hash = adjacent.hash;

        Self { chain, hash }
    }
}

#[repr(align(1))]
#[derive(Debug)]
#[allow(dead_code)]
pub struct AdjacentParentRecord {
    length: u16,
    adjacents: [AdjacentParent; ADJACENT_RECORD_PER_BLOCK],
}

impl AdjacentParentRecord {
    pub fn from_raw(raw: &AdjacentParentRecordRaw) -> Self {
        let length = u16::from_le_bytes(raw.length);
        let mut adjacents = [
            AdjacentParent::from(&AdjacentParentRaw::from_bytes(
                raw.adjacents[0..CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH]
                    .try_into()
                    .expect("Should be able to convert raw adjacent parent to fixed slice"),
            )),
            AdjacentParent::from(&AdjacentParentRaw::from_bytes(
                raw.adjacents[CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH
                    ..(CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH) * 2]
                    .try_into()
                    .expect("Should be able to convert raw adjacent parent to fixed slice"),
            )),
            AdjacentParent::from(&AdjacentParentRaw::from_bytes(
                raw.adjacents[(CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH) * 2
                    ..(CHAIN_BYTES_LENGTH + DIGEST_BYTES_LENGTH) * 3]
                    .try_into()
                    .expect("Should be able to convert raw adjacent parent to fixed slice"),
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
