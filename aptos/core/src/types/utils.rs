// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use anyhow::{anyhow, Result};

/// Size in bytes for an enum variant representation.
pub const ENUM_VARIANT_LEN: usize = 1;

/// Size of a u64 representation in bytes.
pub const U64_SIZE: usize = 8;

/// Relative offset increments for the voting power field in the [`crate::types::ledger_info::LedgerInfo`] struct.
pub const VOTING_POWER_OFFSET_INCR: usize = U64_SIZE;

/// Size of the LEB128 representation of a public key vector length.
pub const LEB128_PUBKEY_LEN: usize = 1;

/// Reads a LEB128 encoded number from a byte slice.
///
/// This function takes a byte slice as input and returns a tuple of the parsed number and the number of bytes read.
/// It reads bytes from the input slice, treating each as a 7-bit digit of the number being decoded.
/// The least significant bit of each byte is used as a continuation flag: if the bit is set, then the next byte is also part of the number.
/// The function stops when it encounters a byte with the continuation flag not set, or when it has read enough bytes to fill a `u64`.
/// If the input is too short to contain a complete number, or if a number too large to fit in a `u64` is encountered, an error is returned.
///
/// # Arguments
///
/// * `input` - A byte slice containing the LEB128 encoded number.
///
/// # Returns
///
/// A Result containing a tuple of the parsed number and the number of bytes read, or an error if the decoding fails.
pub fn read_leb128(input: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut position: usize = 0;

    for byte in input {
        let value = u64::from(*byte);
        let digit = value & 0x7F;
        if shift < 64 && digit << shift >> shift == digit {
            result |= digit << shift;
            position += 1;
            if value & 0x80 == 0 {
                return Ok((result, position));
            }
            shift += 7;
        } else {
            return Err(anyhow!("Overflow during LEB128 decoding"));
        }
    }

    Err(anyhow!("Unexpected end of input during LEB128 decoding"))
}

/// Writes a number as LEB128 encoded bytes.
///
/// This function takes a `u64` number as input and returns a `Vec<u8>` representing the LEB128 encoded version of the number.
/// It creates an empty `Vec<u8>` to hold the result, and starts a loop that continues until the input number is zero.
/// In each iteration of the loop, it takes the least significant 7 bits of the number.
/// If the number after shifting right by 7 bits is not zero, it sets the high bit of this 7-bit chunk.
/// It appends the 7-bit chunk to the result vector and right shifts the number by 7 bits.
/// After the loop, it returns the result vector.
///
/// # Arguments
///
/// * `value` - The `u64` number to be encoded.
///
/// # Returns
///
/// A `Vec<u8>` representing the LEB128 encoded version of the input number.
pub fn write_leb128(mut value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if value == 0 {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        test_serialize_case(0, "00");
        test_serialize_case(1, "01");
        test_serialize_case(2, "02");
        test_serialize_case(3, "03");
        test_serialize_case(4, "04");
        test_serialize_case(5, "05");
        test_serialize_case(6, "06");
        test_serialize_case(7, "07");
        test_serialize_case(8, "08");
        test_serialize_case(9, "09");
        test_serialize_case(10, "0A");
        test_serialize_case(11, "0B");
        test_serialize_case(12, "0C");
        test_serialize_case(13, "0D");
        test_serialize_case(14, "0E");
        test_serialize_case(15, "0F");
        test_serialize_case(16, "10");
        test_serialize_case(17, "11");
        test_serialize_case(624485, "E58E26");
        test_serialize_case(u64::MAX, "FFFFFFFFFFFFFFFFFF01");
    }

    #[test]
    fn test_deserialize() {
        test_deserialize_case("00", 0, 1);
        test_deserialize_case("01", 1, 1);
        test_deserialize_case("E58E26", 624485, 3);
        test_deserialize_case("FFFFFFFFFFFFFFFFFF01", u64::MAX, 10);
    }

    fn test_serialize_case(value: u64, expected: &str) {
        let bytes = write_leb128(value);
        assert_eq!(bytes, hex::decode(expected).unwrap())
    }

    fn test_deserialize_case(bytes: &str, expected: u64, expected_num_bytes: usize) {
        let buffer = hex::decode(bytes).unwrap();
        let (value, num_bytes) = read_leb128(&buffer).unwrap();

        assert_eq!(num_bytes, expected_num_bytes);
        assert_eq!(value, expected);
    }
}
