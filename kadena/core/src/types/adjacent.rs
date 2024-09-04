// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

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

impl From<&AdjacentParentRaw> for AdjacentParent {
    fn from(raw: &AdjacentParentRaw) -> Self {
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
    adjacents: [AdjacentParent; 3],
}

impl AdjacentParentRecord {
    pub fn from_raw(raw: &AdjacentParentRecordRaw) -> Self {
        let length = u16::from_le_bytes(raw.length);
        let mut adjacents = [
            AdjacentParent::from(&AdjacentParentRaw::from_bytes(
                raw.adjacents[0..36].try_into().unwrap(),
            )),
            AdjacentParent::from(&AdjacentParentRaw::from_bytes(
                raw.adjacents[36..72].try_into().unwrap(),
            )),
            AdjacentParent::from(&AdjacentParentRaw::from_bytes(
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
