// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::{BYTES_32_LEN, U64_LEN};
use anyhow::anyhow;
use std::cmp;

/// Bytes length of an offset encoded for variable length fields in SSZ.
pub const OFFSET_BYTE_LENGTH: usize = 4;

/// Utility method to extract the N bytes at a given cursor from a byte array.
///
/// # Arguments
///
/// * `structure` - The name of the structure being extracted.
/// * `bytes` - The byte array to extract from.
/// * `cursor` - The current cursor position in the byte array.
///
/// # Returns
///
/// A tuple containing the new cursor position and the extracted bytes.
pub fn extract_fixed_bytes<const N: usize>(
    structure: &str,
    bytes: &[u8],
    cursor: usize,
) -> Result<(usize, [u8; N]), TypesError> {
    if cursor + N > bytes.len() {
        return Err(serde_error!(
            structure,
            "Not enough bytes to extract fixed bytes"
        ));
    }
    let result = bytes[cursor..cursor + N]
        .try_into()
        .map_err(|_| serde_error!(structure, "Invalid fixed bytes"))?;

    Ok((cursor + N, result))
}

/// Utility method to extract a u64 from a little-endian byte array at a given cursor.
///
/// # Arguments
///
/// * `structure` - The name of the structure being extracted.
/// * `bytes` - The byte array to extract from.
/// * `cursor` - The current cursor position in the byte array.
///
/// # Returns
///
/// A tuple containing the new cursor position and the extracted u64.
pub fn extract_u64(
    structure: &str,
    bytes: &[u8],
    cursor: usize,
) -> Result<(usize, u64), TypesError> {
    if cursor + U64_LEN > bytes.len() {
        return Err(serde_error!(structure, "Not enough bytes to extract u64"));
    }
    let result = u64::from_le_bytes(
        bytes[cursor..cursor + U64_LEN]
            .try_into()
            .map_err(|_| serde_error!(structure, "Invalid u64 bytes"))?,
    );

    Ok((cursor + U64_LEN, result))
}

/// Utility method to extract a u32 from a little-endian byte array at a given cursor.
///
/// # Arguments
///
/// * `structure` - The name of the structure being extracted.
/// * `bytes` - The byte array to extract from.
/// * `cursor` - The current cursor position in the byte array.
///
/// # Returns
///
/// A tuple containing the new cursor position and the extracted u32.
pub fn extract_u32(
    structure: &str,
    bytes: &[u8],
    cursor: usize,
) -> Result<(usize, u32), TypesError> {
    if cursor + OFFSET_BYTE_LENGTH > bytes.len() {
        return Err(serde_error!(structure, "Not enough bytes to extract u32"));
    }
    let result = u32::from_le_bytes(
        bytes[cursor..cursor + OFFSET_BYTE_LENGTH]
            .try_into()
            .map_err(|_| serde_error!(structure, "Invalid u32 bytes"))?,
    );

    Ok((cursor + OFFSET_BYTE_LENGTH, result))
}

/// Utility to convert a slice of bits into a slice of bytes.
///
/// # Arguments
///
/// * `bits` - The slice of bits to convert.
///
/// # Returns
///
/// A vector of bytes.
pub fn pack_bits(bits: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0;
        for (i, &bit) in chunk.iter().enumerate() {
            match bit {
                0 | 1 => byte |= bit << i,
                _ => {
                    return Err(anyhow!(
                        "Input array contains values other than 0 or 1".to_string()
                    ))
                }
            }
        }
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Utility to convert a slice of bytes into a slice of bits.
///
/// # Arguments
///
/// * `bytes` - The slice of bytes to convert.
/// * `num_bits` - The number of bits to convert.
///
/// # Returns
///
/// A vector of bits.
pub fn unpack_bits(bytes: &[u8], num_bits: usize) -> Vec<u8> {
    (0..num_bits)
        .map(|i| (bytes[i / 8] >> (i % 8)) & 1)
        .collect()
}

/// Utility to convert a slice of bytes into an array of 32 bytes.
///
/// # Arguments
///
/// * `bytes` - The slice of bytes to convert.
///
/// # Returns
///
/// An array of 32 bytes.
pub fn u64_to_bytes32(u: u64) -> [u8; BYTES_32_LEN] {
    let mut bytes = [0; BYTES_32_LEN];
    bytes[0..8].copy_from_slice(&u.to_le_bytes());
    bytes
}

/// Utility to convert a slice of bytes into an array of 32 bytes.
///
/// # Arguments
///
/// * `bytes` - The slice of bytes to convert.
///
/// # Returns
///
/// An array of 32 bytes.
///
/// # Notes
///
/// If the input slice is longer than 32 bytes, the output will be truncated.
pub fn bytes_array_to_bytes32(bytes: &[u8]) -> [u8; BYTES_32_LEN] {
    let mut padded = [0; BYTES_32_LEN];
    padded[..cmp::min(bytes.len(), BYTES_32_LEN)].copy_from_slice(bytes);
    padded
}
