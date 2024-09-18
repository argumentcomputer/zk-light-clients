use crate::crypto::error::CryptoError;
use crate::crypto::hash::sha512::{hash_inner, hash_tagged_data};
use crate::crypto::hash::HashValue;
use crate::merkle::proof::MerkleProof;
use crate::merkle::subject::Subject;
use crate::merkle::TRANSACTION_TAG;
use crate::types::error::ValidationError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;

#[derive(Clone, Debug, Getters)]
#[getset(get = "pub")]
pub struct Spv {
    algorithm: String,
    chain: u32,
    object: MerkleProof,
    subject: Subject,
}

impl Spv {
    pub fn new(algorithm: String, chain: u32, object: MerkleProof, subject: Subject) -> Self {
        Self {
            algorithm,
            chain,
            object,
            subject,
        }
    }

    pub fn verify(&self, expected_root: &HashValue) -> Result<bool, ValidationError> {
        // Hash subject for base leaf
        let mut current_hash = hash_tagged_data(
            TRANSACTION_TAG,
            &URL_SAFE_NO_PAD
                .decode(self.subject().input().as_bytes())
                .map_err(|err| ValidationError::InvalidBase64 { source: err.into() })?,
        )
        .map_err(|err| ValidationError::HashError { source: err.into() })?;

        // Process each step in the proof
        for step in self.object().steps().iter() {
            // Combine the current hash with the proof hash based on the position (left/right)
            current_hash = match step.side() {
                0x00 => hash_inner(&current_hash.to_vec(), &step.hash().to_vec())
                    .map_err(|err| ValidationError::HashError { source: err.into() })?,
                0x01 => hash_inner(&step.hash().to_vec(), &current_hash.to_vec())
                    .map_err(|err| ValidationError::HashError { source: err.into() })?,
                _ => {
                    return Err(ValidationError::InvalidPosition {
                        value: *step.side(),
                    })
                }
            };
        }

        println!("  Current hash: {:?}", current_hash);
        println!("  Expected root: {:?}", expected_root);

        Ok(&current_hash == expected_root)
    }
}
