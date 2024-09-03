use sha2::{Digest, Sha512Trunc256};

// Hash functions for Merkle tree nodes
// cf. https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#merke-log-trees
pub type ChainwebHash = Sha512Trunc256;

pub const fn tag_bytes(tag: u16) -> [u8; 2] {
    tag.to_be_bytes()
}

pub fn hash_data(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x0];
    ChainwebHash::digest([x, &tag_bytes(tag), bytes].concat().as_slice()).to_vec()
}

pub fn hash_root(bytes: &[u8; 32]) -> Vec<u8> {
    bytes.to_vec()
}

pub fn hash_inner(left: &[u8], right: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x1];
    ChainwebHash::digest([x, left, right].concat().as_slice()).to_vec()
}
