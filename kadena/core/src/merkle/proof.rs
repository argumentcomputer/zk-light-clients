use crate::crypto::hash::HashValue;
use crate::types::error::TypesError;
use crate::types::header::chain::HASH_BYTES_LENGTH;
use crate::types::{U32_BYTES_LENGTH, U64_BYTES_LENGTH};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;

pub const MERKLE_PROOF_BASE_BYTES_LENGTH: usize = U32_BYTES_LENGTH + U64_BYTES_LENGTH;

pub const STEP_BYTES_LENGTH: usize = HASH_BYTES_LENGTH + 1;

#[derive(Clone, Debug, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct MerkleProof {
    subject_position: u64,
    steps: Vec<Steps>,
}

impl MerkleProof {
    /// Create a new `MerkleProof` with the given subject position and steps.
    ///
    /// # Arguments
    ///
    /// * `subject_position` - The position of the subject in the tree.
    /// * `steps` - The steps of the proof.
    ///
    /// # Returns
    ///
    /// A new `MerkleProof`.
    ///
    /// # Notes
    ///
    /// Currently used for testing purposes only.
    #[cfg(test)]
    pub(crate) const fn new(subject_position: u64, steps: Vec<Steps>) -> Self {
        Self {
            subject_position,
            steps,
        }
    }

    /// Decode a `MerkleProof` from base64.
    ///
    /// # Arguments
    ///
    /// * `input` - The base64 encoded input.
    ///
    /// # Returns
    ///
    /// The `MerkleProof`.
    pub fn from_base64(input: &[u8]) -> Result<Self, TypesError> {
        let decoded_input =
            URL_SAFE_NO_PAD
                .decode(input)
                .map_err(|err| TypesError::DeserializationError {
                    structure: "MerkleProof".into(),
                    source: err.into(),
                })?;

        Self::from_bytes(&decoded_input)
    }

    /// Deserialize a `MerkleProof` from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes to deserialize.
    ///
    /// # Returns
    ///
    /// The `MerkleProof`.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < MERKLE_PROOF_BASE_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "MerkleProof".to_string(),
                actual: bytes.len(),
                minimum: MERKLE_PROOF_BASE_BYTES_LENGTH,
            });
        }

        // Read step count (first 4 bytes)
        let step_count = u32::from_be_bytes(
            bytes[0..U32_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 4 bytes for u32"),
        );
        bytes = &bytes[U32_BYTES_LENGTH..];

        // Read subject position (next 8 bytes)
        let subject_position = u64::from_be_bytes(
            bytes[0..U64_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 8 bytes for u64"),
        );
        bytes = &bytes[U64_BYTES_LENGTH..];

        // Verify size
        let expected_size = step_count as usize * (STEP_BYTES_LENGTH);
        if bytes.len() != expected_size {
            return Err(TypesError::InvalidLength {
                structure: "MerkleProof".to_string(),
                expected: expected_size,
                actual: bytes.len(),
            });
        }

        // Parse the rest of the bytes (steps)
        let mut steps = Vec::new();
        for chunk in bytes.chunks(STEP_BYTES_LENGTH) {
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

    /// Convert the `MerkleProof` to bytes.
    ///
    /// # Returns
    ///
    /// The bytes of the `MerkleProof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write step count
        bytes.extend_from_slice(&(self.steps.len() as u32).to_be_bytes());

        // Write subject position
        bytes.extend_from_slice(&self.subject_position.to_be_bytes());

        // Write steps
        for step in self.steps.iter() {
            bytes.push(*step.side());
            bytes.extend_from_slice(step.hash().as_ref());
        }

        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Steps {
    side: u8,
    hash: HashValue,
}

impl Steps {
    /// Create a new `Steps` with the given side and hash.
    ///
    /// # Arguments
    ///
    /// * `side` - The side of the step.
    /// * `hash` - The sibling hash of the step.
    ///
    /// # Returns
    ///
    /// A new `Steps`.
    ///
    /// # Notes
    ///
    /// Currently used for testing purposes only.
    #[cfg(test)]
    pub(crate) const fn new(side: u8, hash: HashValue) -> Self {
        Self { side, hash }
    }
}

#[cfg(all(test, feature = "kadena"))]
mod test {
    use crate::merkle::proof::{
        MerkleProof, Steps, MERKLE_PROOF_BASE_BYTES_LENGTH, STEP_BYTES_LENGTH,
    };
    use crate::test_utils::random_hash;

    const STEPS_COUNT: usize = 15;

    #[test]
    fn test_serde_proof() {
        let subject_position = 15;
        let steps = vec![Steps::new(1, random_hash()); 15];
        let proof = MerkleProof::new(subject_position, steps);

        let bytes = proof.to_bytes();
        assert_eq!(
            bytes.len(),
            STEPS_COUNT * (STEP_BYTES_LENGTH) + MERKLE_PROOF_BASE_BYTES_LENGTH
        );

        let deserialized_proof = MerkleProof::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized_proof, proof);
    }
}
