// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::deserialization_error;
use crate::types::error::TypesError;

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
