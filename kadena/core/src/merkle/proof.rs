use crate::crypto::hash::HashValue;
use crate::types::error::TypesError;
use crate::types::header::chain::HASH_BYTES_LENGTH;
use crate::types::{U32_BYTES_LENGTH, U64_BYTES_LENGTH};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;

pub const MERKLE_PROOF_BASE_BYTES_LENGTH: usize = U32_BYTES_LENGTH + U64_BYTES_LENGTH;

pub const STEP_BYTES_LENGTH: usize = HASH_BYTES_LENGTH + 1;

#[derive(Clone, Debug, Getters)]
#[getset(get = "pub")]
pub struct MerkleProof {
    subject_position: u64,
    steps: Vec<Steps>,
}

impl MerkleProof {
    pub fn from_base64(mut input: &[u8]) -> Result<Self, TypesError> {
        let mut decoded_input =
            URL_SAFE_NO_PAD
                .decode(&mut input)
                .map_err(|err| TypesError::DeserializationError {
                    structure: "MerkleProof".into(),
                    source: err.into(),
                })?;

        if decoded_input.len() < MERKLE_PROOF_BASE_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "MerkleProof".to_string(),
                actual: decoded_input.len(),
                minimum: MERKLE_PROOF_BASE_BYTES_LENGTH,
            });
        }

        // Read step count (first 4 bytes)
        let step_count = u32::from_be_bytes(
            decoded_input[0..U32_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 4 bytes for u32"),
        );
        decoded_input = decoded_input[U32_BYTES_LENGTH..].to_vec();

        // Read subject position (next 8 bytes)
        let subject_position = u64::from_be_bytes(
            decoded_input[0..U64_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 8 bytes for u64"),
        );
        decoded_input = decoded_input[U64_BYTES_LENGTH..].to_vec();
        dbg!(step_count, subject_position);

        // Verify size
        let expected_size = step_count as usize * (STEP_BYTES_LENGTH);
        if decoded_input.len() != expected_size {
            return Err(TypesError::InvalidLength {
                structure: "MerkleProof".to_string(),
                expected: expected_size,
                actual: decoded_input.len(),
            });
        }

        // Parse the rest of the bytes (steps)
        let mut steps = Vec::new();
        for chunk in decoded_input.chunks(STEP_BYTES_LENGTH) {
            let side = chunk[0]; // Side (0x00 for left, 0x01 for right)
            let hash = HashValue::from_slice(&chunk[1..STEP_BYTES_LENGTH]).map_err(|err| {
                TypesError::DeserializationError {
                    structure: "MerkleProof".into(),
                    source: err.into(),
                }
            })?; // The hash
            steps.push(Steps { side, hash });
        }

        Ok(Self {
            subject_position,
            steps,
        })
    }
}

#[derive(Clone, Debug, Getters)]
#[getset(get = "pub")]
pub struct Steps {
    side: u8,
    hash: HashValue,
}
