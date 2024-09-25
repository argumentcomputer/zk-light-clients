// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # SPV Prover module
//!
//! This module provides the prover implementation for the SPV proof. The prover
//! is responsible for generating, executing, proving, and verifying proofs for the light client.

use crate::proofs::error::ProverError;
use crate::proofs::{ProofType, Prover, ProvingMode};
use anyhow::Result;
use getset::Getters;
use kadena_lc_core::crypto::hash::HashValue;
use kadena_lc_core::crypto::U256;
use kadena_lc_core::merkle::spv::Spv;
use kadena_lc_core::types::error::TypesError;
use kadena_lc_core::types::header::chain::HASH_BYTES_LENGTH;
use kadena_lc_core::types::header::layer::ChainwebLayerHeader;
use kadena_lc_core::types::U64_BYTES_LENGTH;
use kadena_programs::SPV_PROGRAM;
use sphinx_sdk::{
    ProverClient, SphinxProvingKey, SphinxPublicValues, SphinxStdin, SphinxVerifyingKey,
};

/// The prover for the spv proof.
pub struct SpvProver {
    client: ProverClient,
    keys: (SphinxProvingKey, SphinxVerifyingKey),
}

impl Default for SpvProver {
    fn default() -> Self {
        Self::new()
    }
}

impl SpvProver {
    /// Create a new `SpvProver`.
    ///
    /// # Returns
    ///
    /// A new `SpvProver`.
    pub fn new() -> Self {
        let client = ProverClient::new();
        let keys = client.setup(SPV_PROGRAM);

        Self { client, keys }
    }

    /// Gets a `SphinxVerifyingKey`.
    ///
    /// # Returns
    ///
    /// A `SphinxVerifyingKey` that can be used for verifying the spv proof.
    pub const fn get_vk(&self) -> &SphinxVerifyingKey {
        &self.keys.1
    }
}

/// The input for the spv proof.
#[derive(Debug, Eq, PartialEq)]
pub struct SpvIn {
    layer_block_headers: Vec<ChainwebLayerHeader>,
    spv: Spv,
    expected_root: HashValue,
}

impl SpvIn {
    /// Create a new `SpvIn`.
    ///
    /// # Arguments
    ///
    /// * `layer_block_headers` - The layer block headers.
    ///
    /// # Returns
    ///
    /// A new `SpvIn`.
    pub const fn new(
        layer_block_headers: Vec<ChainwebLayerHeader>,
        spv: Spv,
        expected_root: HashValue,
    ) -> Self {
        Self {
            layer_block_headers,
            spv,
            expected_root,
        }
    }

    /// Serialize the `SpvIn` struct to bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the serialized `SpvIn` struct.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Serialized list length and elements
        let chainweb_layer_bytes = ChainwebLayerHeader::serialize_list(&self.layer_block_headers);
        bytes.extend_from_slice(&(chainweb_layer_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&chainweb_layer_bytes);

        // Serialized spv length and bytes
        let spv_bytes = self.spv.to_bytes();
        bytes.extend_from_slice(&(spv_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&spv_bytes);

        // Fixed length
        bytes.extend_from_slice(self.expected_root.as_ref());

        bytes
    }

    /// Deserialize a `SpvIn` struct from bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized `SpvIn` struct or a `TypesError`.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let input_length = bytes.len();

        if bytes.len() < U64_BYTES_LENGTH * 2 + HASH_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "SpvIn".to_string(),
                actual: bytes.len(),
                minimum: 32,
            });
        }

        // Get list length
        let list_length = u64::from_le_bytes(
            bytes[0..U64_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 8 bytes for u64"),
        ) as usize;
        bytes = &bytes[U64_BYTES_LENGTH..];

        if input_length < list_length + U64_BYTES_LENGTH * 2 + HASH_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "SpvIn".to_string(),
                actual: bytes.len(),
                minimum: list_length + U64_BYTES_LENGTH * 2 + HASH_BYTES_LENGTH,
            });
        }

        // Get list
        let layer_block_headers = ChainwebLayerHeader::deserialize_list(&bytes[0..list_length])?;
        bytes = &bytes[list_length..];

        // Get spv length
        let spv_length = u64::from_le_bytes(
            bytes[0..U64_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 8 bytes for u64"),
        ) as usize;
        bytes = &bytes[U64_BYTES_LENGTH..];

        if input_length != list_length + spv_length + U64_BYTES_LENGTH * 2 + HASH_BYTES_LENGTH {
            return Err(TypesError::InvalidLength {
                structure: "SpvIn".to_string(),
                actual: bytes.len(),
                expected: list_length + spv_length + U64_BYTES_LENGTH * 2 + HASH_BYTES_LENGTH,
            });
        }

        // Get spv
        let spv = Spv::from_bytes(&bytes[0..spv_length])?;
        bytes = &bytes[spv_length..];

        // Get expected root
        let expected_root = HashValue::new(
            bytes[0..HASH_BYTES_LENGTH]
                .try_into()
                .expect("Should be able to extract 32 bytes for HashValue"),
        );

        Ok(Self {
            layer_block_headers,
            spv,
            expected_root,
        })
    }
}

/// The output for the spv proof.
#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct SpvOut {
    first_layer_block_header_hash: HashValue,
    target_layer_block_header_hash: HashValue,
    confirmation_work: U256,
    subject_hash: HashValue,
}

impl From<&mut SphinxPublicValues> for SpvOut {
    fn from(public_values: &mut SphinxPublicValues) -> Self {
        let confirmation_work = U256::from_little_endian(&public_values.read::<[u8; 32]>());
        let first_layer_block_header_hash = HashValue::new(public_values.read::<[u8; 32]>());
        let target_layer_block_header_hash = HashValue::new(public_values.read::<[u8; 32]>());
        let subject_hash = HashValue::new(public_values.read::<[u8; 32]>());

        Self {
            confirmation_work,
            first_layer_block_header_hash,
            target_layer_block_header_hash,
            subject_hash,
        }
    }
}

impl Prover for SpvProver {
    const PROGRAM: &'static [u8] = SPV_PROGRAM;
    type Error = ProverError;
    type StdIn = SpvIn;
    type StdOut = SpvOut;

    fn generate_sphinx_stdin(&self, inputs: &Self::StdIn) -> Result<SphinxStdin, Self::Error> {
        let mut stdin = SphinxStdin::new();
        stdin.write(&ChainwebLayerHeader::serialize_list(
            &inputs.layer_block_headers,
        ));
        stdin.write(&inputs.spv.to_bytes());
        stdin.write(&inputs.expected_root.to_vec());

        Ok(stdin)
    }

    fn execute(&self, inputs: &Self::StdIn) -> Result<Self::StdOut, Self::Error> {
        sphinx_sdk::utils::setup_logger();

        let stdin = self.generate_sphinx_stdin(inputs)?;

        let (mut public_values, _) = self
            .client
            .execute(Self::PROGRAM, stdin)
            .run()
            .map_err(|err| ProverError::Execution { source: err.into() })?;

        Ok(SpvOut::from(&mut public_values))
    }

    fn prove(&self, inputs: &Self::StdIn, mode: ProvingMode) -> Result<ProofType, Self::Error> {
        let stdin = self.generate_sphinx_stdin(inputs)?;

        match mode {
            ProvingMode::STARK => self
                .client
                .prove(&self.keys.0, stdin)
                .run()
                .map_err(|err| ProverError::Proving {
                    proof_type: mode.into(),
                    source: err.into(),
                })
                .map(ProofType::STARK),
            ProvingMode::SNARK => self
                .client
                .prove(&self.keys.0, stdin)
                .plonk()
                .run()
                .map_err(|err| ProverError::Proving {
                    proof_type: mode.into(),
                    source: err.into(),
                })
                .map(ProofType::SNARK),
        }
    }

    fn verify(&self, proof: &ProofType) -> Result<(), Self::Error> {
        let vk = &self.keys.1;

        match proof {
            ProofType::STARK(proof) | ProofType::SNARK(proof) => self
                .client
                .verify(proof, vk)
                .map_err(|err| ProverError::Verification { source: err.into() }),
        }
    }
}

#[cfg(all(test, feature = "kadena"))]
mod test {
    use super::*;
    use kadena_lc_core::merkle::subject::Subject;
    use kadena_lc_core::test_utils::get_test_assets;

    #[test]
    fn test_execute_spv() {
        let test_assets = get_test_assets();

        let prover = SpvProver::new();

        let spv_inputs = SpvIn {
            layer_block_headers: test_assets.layer_headers().clone(),
            spv: test_assets.spv().clone(),
            expected_root: *test_assets.expected_root(),
        };

        let spv_out = prover.execute(&spv_inputs).unwrap();

        let confirmation_work = ChainwebLayerHeader::cumulative_produced_work(
            test_assets.layer_headers()
                [test_assets.layer_headers().len() / 2..test_assets.layer_headers().len() - 1]
                .to_vec(),
        )
        .expect("Should be able to calculate cumulative work");

        assert_eq!(spv_out.confirmation_work, confirmation_work,);
        assert_eq!(
            spv_out.first_layer_block_header_hash,
            test_assets
                .layer_headers()
                .first()
                .expect("Should have a first header")
                .header_root()
                .expect("Should have a header root"),
        );
        assert_eq!(
            spv_out.target_layer_block_header_hash,
            test_assets.layer_headers()[test_assets.layer_headers().len() / 2]
                .header_root()
                .expect("Should have a header root"),
        );
        assert_eq!(
            test_assets
                .spv()
                .subject()
                .hash_as_leaf()
                .expect("Should be able to hash subject"),
            spv_out.subject_hash
        )
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_stark_spv() {
        use std::time::Instant;

        let test_assets = get_test_assets();

        let prover = SpvProver::new();

        let new_period_inputs = SpvIn {
            layer_block_headers: test_assets.layer_headers().clone(),
            spv: test_assets.spv().clone(),
            expected_root: *test_assets.expected_root(),
        };

        println!("Starting STARK proving for spv...");
        let start = Instant::now();

        let _ = prover
            .prove(&new_period_inputs, ProvingMode::STARK)
            .unwrap();
        println!("Proving took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_snark_spv() {
        use std::time::Instant;

        let test_assets = get_test_assets();

        let prover = SpvProver::new();

        let new_period_inputs = SpvIn {
            layer_block_headers: test_assets.layer_headers().clone(),
            spv: test_assets.spv().clone(),
            expected_root: *test_assets.expected_root(),
        };

        println!("Starting SNARK proving for spv...");
        let start = Instant::now();

        let _ = prover
            .prove(&new_period_inputs, ProvingMode::SNARK)
            .unwrap();
        println!("Proving took {:?}", start.elapsed());
    }
}
