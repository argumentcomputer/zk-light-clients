// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::types::error::TypesError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha512Trunc256};

// Hash functions for Merkle tree nodes
// cf. https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#merke-log-trees
pub type ChainwebHash = Sha512Trunc256;

pub const TAG_BYTES_LENGTH: usize = 2;
pub const DIGEST_BYTES_LENGTH: usize = 32;

pub fn hash_from_base64(base64: &[u8]) -> Result<[u8; DIGEST_BYTES_LENGTH], TypesError> {
    let decoded =
        URL_SAFE_NO_PAD
            .decode(base64)
            .map_err(|err| TypesError::DeserializationError {
                structure: "digest".to_string(),
                source: err.into(),
            })?;
    let mut arr = [0u8; DIGEST_BYTES_LENGTH];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

pub const fn tag_bytes(tag: u16) -> [u8; TAG_BYTES_LENGTH] {
    tag.to_be_bytes()
}

pub fn hash_data(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x0];
    ChainwebHash::digest([x, &tag_bytes(tag), bytes].concat().as_slice()).to_vec()
}

pub fn hash_root(bytes: &[u8; DIGEST_BYTES_LENGTH]) -> Vec<u8> {
    bytes.to_vec()
}

pub fn hash_inner(left: &[u8], right: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x1];
    ChainwebHash::digest([x, left, right].concat().as_slice()).to_vec()
}
