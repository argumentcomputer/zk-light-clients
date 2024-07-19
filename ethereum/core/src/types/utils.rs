// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::deserialization_error;
use crate::types::error::TypesError;
use crate::types::{Bytes32, BYTES_32_LEN};
use anyhow::anyhow;
use std::cmp;

/// Bytes length of an offset encoded for variable length fields in SSZ.
pub const OFFSET_BYTE_LENGTH: usize = 4;

/// Length of u64 in bytes.
pub const U64_LEN: usize = (u64::BITS / 8) as usize;

/// Genesis root of the Beacon chain.
pub const GENESIS_ROOT: Bytes32 = [
    75, 54, 61, 185, 78, 40, 97, 32, 215, 110, 185, 5, 52, 15, 221, 78, 84, 191, 233, 240, 107,
    243, 63, 246, 207, 90, 210, 127, 81, 27, 254, 149,
];
/// Domain type for the Beacon chain.
pub const DOMAIN_BEACON_DENEB: Bytes32 = [
    7, 0, 0, 0, 106, 149, 161, 169, 103, 133, 93, 103, 109, 72, 190, 105, 136, 59, 113, 38, 7, 249,
    82, 213, 25, 141, 15, 86, 119, 86, 70, 54,
];

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
        return Err(deserialization_error!(
            structure,
            "Not enough bytes to extract fixed bytes"
        ));
    }
    let result = bytes[cursor..cursor + N]
        .try_into()
        .map_err(|_| deserialization_error!(structure, "Invalid fixed bytes"))?;

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
        return Err(deserialization_error!(
            structure,
            "Not enough bytes to extract u64"
        ));
    }
    let result = u64::from_le_bytes(
        bytes[cursor..cursor + U64_LEN]
            .try_into()
            .map_err(|_| deserialization_error!(structure, "Invalid u64 bytes"))?,
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
        return Err(deserialization_error!(
            structure,
            "Not enough bytes to extract u32"
        ));
    }
    let result = u32::from_le_bytes(
        bytes[cursor..cursor + OFFSET_BYTE_LENGTH]
            .try_into()
            .map_err(|_| deserialization_error!(structure, "Invalid u32 bytes"))?,
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

/// Utility to convert a list of bytes slice to an SSZ encoded  object.
///
/// # Arguments
///
/// * `list` - The list of bytes to convert.
///
/// # Returns
///
/// A vector of bytes.
pub fn ssz_encode_list_bytes(list: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];

    if list.is_empty() {
        return bytes;
    }

    // First element offset
    let mut element_offset = list.len() * OFFSET_BYTE_LENGTH;
    bytes.extend_from_slice(&(element_offset as u32).to_le_bytes());

    // Grow with offset and create the serialized element slice
    let mut serialized_elements = vec![];

    for (i, element) in list.iter().enumerate() {
        if i < list.len() - 1 {
            element_offset += element.len();
            bytes.extend_from_slice(&(element_offset as u32).to_le_bytes());
        }

        serialized_elements.extend_from_slice(element);
    }

    // Finalize list bytes and extend final bytes
    bytes.extend_from_slice(&serialized_elements);

    bytes
}

/// Utility to convert a slice of bytes into a list of bytes.
///
/// # Arguments
///
/// * `bytes` - The slice of bytes to convert.
///
/// # Returns
///
/// A vector of bytes.
pub fn ssz_decode_list_bytes(bytes: &[u8]) -> Result<Vec<Vec<u8>>, TypesError> {
    let mut list_bytes = vec![];
    if bytes.len() > OFFSET_BYTE_LENGTH {
        let (mut cursor, mut offset) = extract_u32("StorageProof", bytes, 0)?;
        let first_offset = offset as usize;

        loop {
            if cursor == first_offset {
                break;
            }

            let (next_cursor, next_offset) = extract_u32("StorageProof", bytes, cursor)?;
            list_bytes.push(
                bytes
                    .get(offset as usize..next_offset as usize)
                    .ok_or_else(|| TypesError::OutOfBounds {
                        structure: "StorageProof".into(),
                        offset: next_offset as usize,
                        length: bytes.len(),
                    })?
                    .to_vec(),
            );

            cursor = next_cursor;
            offset = next_offset;
        }

        list_bytes.push(
            bytes
                .get(offset as usize..)
                .ok_or_else(|| TypesError::OutOfBounds {
                    structure: "StorageProof".into(),
                    offset: offset as usize,
                    length: bytes.len(),
                })?
                .to_vec(),
        );
    } else if !bytes.is_empty() {
        return Err(TypesError::UnderLength {
            structure: "StorageProof".into(),
            minimum: OFFSET_BYTE_LENGTH,
            actual: bytes.len(),
        });
    }

    Ok(list_bytes)
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

/// Calculate the sync period for a given slot number.
///
/// # Arguments
///
/// * `slot` - The slot number.
///
/// # Returns
///
/// The sync period.
pub fn calc_sync_period(slot: &u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}
