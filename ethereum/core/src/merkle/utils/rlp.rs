// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::merkle::error::RlpError;
use crate::merkle::utils::get_nibble;
use anyhow::{anyhow, Result};
use ethers_core::types::EIP1186ProofResponse;
use ethers_core::utils::rlp::RlpStream;

/// One byte data limit.
///
/// From [the Ethereum documentation](https://ethereum.org/vi/developers/docs/data-structures-and-encoding/rlp/).
const SINGLE_BYTE_LIMIT: u8 = 0x80;
/// Short string limit.
///
/// From [the Ethereum documentation](https://ethereum.org/vi/developers/docs/data-structures-and-encoding/rlp/).
const SHORT_STRING_LIMIT: u8 = 0xb7;
/// Long string limit.
///
/// From [the Ethereum documentation](https://ethereum.org/vi/developers/docs/data-structures-and-encoding/rlp/).
const LONG_STRING_LIMIT: u8 = 0xbf;
/// Short list limit.
///
/// From [the Ethereum documentation](https://ethereum.org/vi/developers/docs/data-structures-and-encoding/rlp/).
const SHORT_LIST_LIMIT: u8 = 0xf7;

/// Empty storage Merkle Patricia trie root hash.
const EMPTY_STORAGE_ROOT: &str = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
/// Empty string (no code) keccak256 hash.
const NO_CODE_KECCAK_HASH: &str =
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

/// Encodes an EIP 1186 response into an RLP encoded account.
///
/// # Arguments
///
/// * `proof` - The EIP 1186 response.
///
/// # Returns
///
/// The RLP encoded account.
pub fn rlp_encode_account(proof: &EIP1186ProofResponse) -> Vec<u8> {
    let mut stream = RlpStream::new_list(4);
    stream.append(&proof.nonce);
    stream.append(&proof.balance);
    stream.append(&proof.storage_hash);
    stream.append(&proof.code_hash);
    let encoded = stream.out();
    encoded.to_vec()
}

/// Converts a byte slice to an integer.
///
/// # Arguments
///
/// * `input` - The byte slice to convert.
///
/// # Returns
///
/// The integer representation of the byte slice.
fn to_integer(input: &[u8]) -> usize {
    if input.is_empty() {
        return 0;
    }
    let result = input.iter().fold(0, |acc, &b| acc * 256 + b as usize);
    result
}

/// Decodes an RLP encoded item.
///
/// # Arguments
///
/// * `input` - The RLP encoded item.
///
/// # Returns
///
/// The decoded item and the remaining data.
fn decode_item(input: &[u8]) -> Result<(Vec<u8>, &[u8]), RlpError> {
    if input.is_empty() {
        return Err(RlpError::EmptyInput);
    }

    let prefix = input[0];

    if prefix < SINGLE_BYTE_LIMIT {
        Ok((vec![prefix], &input[1..]))
    } else if prefix <= SHORT_STRING_LIMIT {
        let str_len = (prefix - SINGLE_BYTE_LIMIT) as usize;
        if input.len() < 1 + str_len {
            return Err(RlpError::InputTooShort {
                decode_type: "short string".into(),
                expected: 1 + str_len,
                actual: input.len(),
            });
        }
        Ok((input[1..1 + str_len].to_vec(), &input[1 + str_len..]))
    } else if prefix <= LONG_STRING_LIMIT {
        let len_of_str_len = (prefix - SHORT_STRING_LIMIT) as usize;
        if input.len() < 1 + len_of_str_len {
            return Err(RlpError::InputTooShort {
                decode_type: "long string length".into(),
                expected: 1 + len_of_str_len,
                actual: input.len(),
            });
        }
        let str_len = to_integer(&input[1..1 + len_of_str_len]);
        if input.len() < 1 + len_of_str_len + str_len {
            return Err(RlpError::InputTooShort {
                decode_type: "long string".into(),
                expected: 1 + len_of_str_len + str_len,
                actual: input.len(),
            });
        }
        Ok((
            input[1 + len_of_str_len..1 + len_of_str_len + str_len].to_vec(),
            &input[1 + len_of_str_len + str_len..],
        ))
    } else if prefix <= SHORT_LIST_LIMIT {
        let list_len = (prefix - SHORT_LIST_LIMIT + 0xc0) as usize;
        if input.len() < 1 + list_len {
            return Err(RlpError::InputTooShort {
                decode_type: "short list".into(),
                expected: 1 + list_len,
                actual: input.len(),
            });
        }
        Ok((input[1..1 + list_len].to_vec(), &input[1 + list_len..]))
    } else {
        let len_of_list_len = (prefix - SHORT_LIST_LIMIT) as usize;
        if input.len() < 1 + len_of_list_len {
            return Err(RlpError::InputTooShort {
                decode_type: "long list length".into(),
                expected: 1 + len_of_list_len,
                actual: input.len(),
            });
        }
        let list_len = to_integer(&input[1..1 + len_of_list_len]);
        if input.len() < 1 + len_of_list_len + list_len {
            return Err(RlpError::InputTooShort {
                decode_type: "long list".into(),
                expected: 1 + len_of_list_len + list_len,
                actual: input.len(),
            });
        }
        Ok((
            input[1 + len_of_list_len..1 + len_of_list_len + list_len].to_vec(),
            &input[1 + len_of_list_len + list_len..],
        ))
    }
}

/// Decodes an RLP encoded list.
///
/// # Arguments
///
/// * `input` - The RLP encoded list.
///
/// # Returns
///
/// The decoded list.
///
/// # Errors
///
/// Returns an error if the input is empty or if there is leftover data after decoding the list.
pub fn decode_list(input: &[u8]) -> Result<Vec<Vec<u8>>, RlpError> {
    if input.is_empty() {
        return Err(RlpError::EmptyInput);
    }

    let mut items = Vec::new();
    let mut rest = input;

    while !rest.is_empty() {
        let (item, remaining) = decode_item(rest)?;
        items.push(item);
        rest = remaining;
    }

    if !rest.is_empty() {
        return Err(RlpError::LeftoverData {
            expected: 0,
            actual: rest.len(),
        });
    }

    Ok(items)
}

/// Checks if an RLP-encoded value corresponds to an empty account.
///
/// # Arguments
///
/// * `value` - The RLP-encoded value.
///
/// # Returns
///
/// `true` if the value corresponds to an empty account, `false` otherwise.
pub fn is_empty_value(value: &[u8]) -> Result<bool> {
    let mut empty_account = vec![];

    // Begin list with 4 items (0xc0 + 4 = 0xc4)
    empty_account.push(0xc4);

    // Append two empty data items (0x80)
    empty_account.push(SINGLE_BYTE_LIMIT);
    empty_account.push(SINGLE_BYTE_LIMIT);

    // Append empty storage hash
    let empty_storage_hash = EMPTY_STORAGE_ROOT;
    empty_account.extend_from_slice(&hex_decode(empty_storage_hash)?);

    // Append empty code hash
    let empty_code_hash = NO_CODE_KECCAK_HASH;
    empty_account.extend_from_slice(&hex_decode(empty_code_hash)?);

    let is_empty_slot = value.len() == 1 && value[0] == 0x80;
    let is_empty_account = value == empty_account;
    Ok(is_empty_slot || is_empty_account)
}

/// Decodes a hexadecimal string into a byte vector.
///
/// # Arguments
///
/// * `s` - The hexadecimal string.
///
/// # Returns
///
/// The byte vector.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| anyhow!(err.to_string()))
}

/// Checks if two paths match.
///
/// # Arguments
///
/// * `p1` - The first path.
/// * `s1` - The offset of the first path.
/// * `p2` - The second path.
/// * `s2` - The offset of the second path.
///
/// # Returns
///
/// `true` if the paths match, `false` otherwise.
pub fn paths_match(p1: &[u8], s1: usize, p2: &[u8], s2: usize) -> bool {
    let len1 = p1.len() * 2 - s1;
    let len2 = p2.len() * 2 - s2;

    if len1 != len2 {
        return false;
    }

    for offset in 0..len1 {
        let n1 = get_nibble(p1, s1 + offset);
        let n2 = get_nibble(p2, s2 + offset);

        if n1 != n2 {
            return false;
        }
    }

    true
}

/// Skips the bytes corresponding to a length value in an
/// RLP-encoded value.
///
/// # Arguments
///
/// * `node` - The RLP-encoded value.
///
/// # Returns
///
/// The number of bytes to skip.
pub const fn skip_length(node: &[u8]) -> usize {
    if node.is_empty() {
        return 0;
    }

    let nibble = get_nibble(node, 0);
    match nibble {
        0 | 2 => 2,
        1 | 3 => 1,
        _ => 0,
    }
}

/// Computes the length of the shared prefix between a path and a node path.
///
/// # Arguments
///
/// * `path` - The path.
/// * `path_offset` - The offset of the path.
/// * `node_path` - The node path.
///
/// # Returns
///
/// The length of the shared prefix.
pub fn shared_prefix_length(path: &[u8], path_offset: usize, node_path: &[u8]) -> usize {
    let skip_length = skip_length(node_path);

    let len = std::cmp::min(
        node_path.len() * 2 - skip_length,
        path.len() * 2 - path_offset,
    );
    let mut prefix_len = 0;

    for i in 0..len {
        let path_nibble = get_nibble(path, i + path_offset);
        let node_path_nibble = get_nibble(node_path, i + skip_length);

        if path_nibble == node_path_nibble {
            prefix_len += 1;
        } else {
            break;
        }
    }

    prefix_len
}
