use crate::crypto::hash::sha512::{hash_data, hash_inner};
use crate::crypto::hash::HashValue;
use crate::merkle::proof::{MerkleProof, MERKLE_PROOF_BASE_BYTES_LENGTH};
use crate::merkle::subject::{Subject, SUBJECT_BASE_BYTES_LENGTH};
use crate::types::error::{TypesError, ValidationError};
use crate::types::U32_BYTES_LENGTH;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;

pub const SPV_BASE_BYTES_LENGTH: usize =
    SUBJECT_BASE_BYTES_LENGTH + MERKLE_PROOF_BASE_BYTES_LENGTH + (U32_BYTES_LENGTH * 2);

#[derive(Clone, Debug, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Spv {
    chain: u32,
    algorithm: String,
    subject: Subject,
    object: MerkleProof,
}

impl Spv {
    /// Create a new `Spv` with the given algorithm, chain, object, and subject.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm used for the proof.
    /// * `chain` - The chain of the proof.
    /// * `object` - The object of the proof.
    ///
    /// # Returns
    ///
    /// A new `Spv`.
    pub const fn new(algorithm: String, chain: u32, object: MerkleProof, subject: Subject) -> Self {
        Self {
            algorithm,
            chain,
            object,
            subject,
        }
    }

    /// Verify the proof against the expected root.
    ///
    /// # Arguments
    ///
    /// * `expected_root` - The expected root of the proof.
    ///
    /// # Returns
    ///
    /// A boolean indicating if the proof is valid.
    pub fn verify(&self, expected_root: &HashValue) -> Result<bool, ValidationError> {
        let x: &[u8] = &[0x0];
        // Hash subject for base leaf
        let mut current_hash = hash_data(
            &[
                x,
            &URL_SAFE_NO_PAD
                .decode(self.subject().input().as_bytes())
                .map_err(|err| ValidationError::InvalidBase64 { source: err.into() })?
            ].concat(),
        )
        .map_err(|err| ValidationError::HashError { source: err.into() })?;

        // Process each step in the proof
        for step in self.object().steps().iter() {
            // Combine the current hash with the proof hash based on the position (left/right)
            current_hash = match step.side() {
                0x00 => hash_inner(step.hash().as_ref(), current_hash.as_ref())
                    .map_err(|err| ValidationError::HashError { source: err.into() })?,
                0x01 => hash_inner(current_hash.as_ref(), step.hash().as_ref())
                    .map_err(|err| ValidationError::HashError { source: err.into() })?,
                _ => {
                    return Err(ValidationError::InvalidPosition {
                        value: *step.side(),
                    })
                }
            };
        }

        Ok(&current_hash == expected_root)
    }

    /// Convert the `Spv` to bytes.
    ///
    /// # Returns
    ///
    /// The bytes of the `Spv`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Add chain
        bytes.extend_from_slice(&self.chain().to_be_bytes());

        // Add algorithm length
        let algorithm_bytes = self.algorithm().as_bytes();
        bytes.extend_from_slice(&(algorithm_bytes.len() as u32).to_be_bytes());

        // Add algorithm
        bytes.extend_from_slice(algorithm_bytes);

        // Add subject length
        bytes.extend_from_slice(&self.subject.to_bytes());

        // Add object
        bytes.extend_from_slice(&self.object.to_bytes());

        bytes
    }

    /// Convert bytes to a `Spv`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes to convert.
    ///
    /// # Returns
    ///
    /// The `Spv` represented by the bytes.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        if bytes.len() < SPV_BASE_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "Spv".to_string(),
                actual: bytes.len(),
                minimum: SPV_BASE_BYTES_LENGTH,
            });
        }

        // Read chain (first 4 bytes)
        let chain = u32::from_be_bytes(
            bytes[0..U32_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 4 bytes for u32"),
        );
        bytes = &bytes[U32_BYTES_LENGTH..];

        // Read algorithm length (next 4 bytes)
        let algorithm_length = u32::from_be_bytes(
            bytes[0..U32_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 4 bytes for u32"),
        ) as usize;
        bytes = &bytes[U32_BYTES_LENGTH..];

        // Read algorithm
        let algorithm = String::from_utf8(bytes[0..algorithm_length].to_vec()).map_err(|err| {
            TypesError::DeserializationError {
                structure: "Spv".into(),
                source: err.into(),
            }
        })?;
        bytes = &bytes[algorithm_length..];

        // Read subject
        let subject = Subject::from_bytes(bytes)?;
        bytes = &bytes[subject.to_bytes().len()..];

        // Read object
        let object = MerkleProof::from_bytes(bytes)?;

        Ok(Self::new(algorithm, chain, object, subject))
    }
}

#[cfg(all(test, feature = "kadena"))]
mod test {
    use crate::merkle::proof::{MerkleProof, Steps, STEP_BYTES_LENGTH};
    use crate::merkle::spv::{Spv, SPV_BASE_BYTES_LENGTH};
    use crate::merkle::subject::Subject;
    use crate::test_utils::{random_hash, random_string};

    const SUBJECT_INPUT_LENGTH: usize = 45;
    const STEPS_COUNT: usize = 15;
    const ALGORITHM_LENGTH: usize = 40;

    #[test]
    fn test_serde_spv() {
        let algorithm = random_string(ALGORITHM_LENGTH);
        let subject = Subject::new(random_string(SUBJECT_INPUT_LENGTH));
        let steps = vec![Steps::new(1, random_hash()); STEPS_COUNT];

        let spv = Spv::new(
            algorithm,
            0,
            MerkleProof::new(STEPS_COUNT as u64, steps),
            subject,
        );

        let bytes = spv.to_bytes();
        assert_eq!(
            bytes.len(),
            SPV_BASE_BYTES_LENGTH
                + STEPS_COUNT * STEP_BYTES_LENGTH
                + ALGORITHM_LENGTH
                + SUBJECT_INPUT_LENGTH
        );

        let deserialized_spv = Spv::from_bytes(&bytes).unwrap();

        assert_eq!(spv, deserialized_spv);
    }
}
