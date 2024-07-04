// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::U64_LEN;

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
