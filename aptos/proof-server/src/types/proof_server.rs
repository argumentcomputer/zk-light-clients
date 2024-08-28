// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use serde::{Deserialize, Serialize};
use sphinx_sdk::SphinxProofWithPublicValues;
use std::fmt::Display;

/// The proving mode for the prover.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProvingMode {
    STARK,
    SNARK,
}

impl ProvingMode {
    /// Returns a boolean indicating if the proving mode is STARK.
    ///
    /// # Returns
    ///
    /// A boolean indicating if the proving mode is STARK.
    pub const fn is_stark(&self) -> bool {
        matches!(self, ProvingMode::STARK)
    }

    /// Returns a serialized representation of the enum.
    ///
    /// # Returns
    ///
    /// A u8 representing the enum.
    pub const fn to_bytes(&self) -> u8 {
        match self {
            ProvingMode::STARK => 0,
            ProvingMode::SNARK => 1,
        }
    }

    /// Returns a ProvingMode from a serialized representation.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized representation of the enum.
    ///
    /// # Returns
    ///
    /// The ProvingMode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes[0] {
            0 => Ok(ProvingMode::STARK),
            1 => Ok(ProvingMode::SNARK),
            _ => Err(anyhow!("Invalid proving mode")),
        }
    }
}
impl From<ProvingMode> for String {
    fn from(mode: ProvingMode) -> String {
        match mode {
            ProvingMode::STARK => "STARK".to_string(),
            ProvingMode::SNARK => "SNARK".to_string(),
        }
    }
}

impl TryFrom<&str> for ProvingMode {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "STARK" => Ok(ProvingMode::STARK),
            "SNARK" => Ok(ProvingMode::SNARK),
            _ => Err(anyhow!("Invalid proving mode")),
        }
    }
}

/// Data structure used as a payload to request an epoch change proof generation from the proof
/// server.
#[derive(Serialize, Deserialize)]
pub struct EpochChangeData {
    pub trusted_state: Vec<u8>,
    pub epoch_change_proof: Vec<u8>,
}

/// Data structure used as a payload to request an inclusion proof generation from the proof server.
#[derive(Serialize, Deserialize)]
pub struct InclusionData {
    pub sparse_merkle_proof_assets: SparseMerkleProofAssets,
    pub transaction_proof_assets: TransactionProofAssets,
    pub validator_verifier_assets: ValidatorVerifierAssets,
}

/// Main request type for the proof server. It can be used to request both inclusion and epoch
/// change proofs, as well as their verification. There are two variants for each type of proof:
/// one using the [`SphinxProof`] type and another using the [`SphinxGroth16Proof`] type.
#[derive(Serialize, Deserialize)]
pub enum Request {
    ProveInclusion(Box<(ProvingMode, InclusionData)>),
    ProveEpochChange(Box<(ProvingMode, EpochChangeData)>),
    VerifyInclusion(SphinxProofWithPublicValues),
    VerifyEpochChange(SphinxProofWithPublicValues),
}

impl Display for &Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::ProveInclusion(_) => write!(f, "ProveInclusion"),
            Request::ProveEpochChange(_) => write!(f, "ProveEpochChange"),
            Request::VerifyInclusion(_) => write!(f, "VerifyInclusion"),
            Request::VerifyEpochChange(_) => write!(f, "VerifyEpochChange"),
        }
    }
}
