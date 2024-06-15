// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use serde::{Deserialize, Serialize};
use sphinx_sdk::{SphinxGroth16Proof, SphinxProof};
use std::fmt::Display;

#[derive(Serialize, Deserialize)]
pub struct EpochChangeData {
    pub trusted_state: Vec<u8>,
    pub epoch_change_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct InclusionData {
    pub sparse_merkle_proof_assets: SparseMerkleProofAssets,
    pub transaction_proof_assets: TransactionProofAssets,
    pub validator_verifier_assets: ValidatorVerifierAssets,
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    ProveInclusion(InclusionData),
    ProveEpochChange(EpochChangeData),
    VerifyInclusion(SphinxProof),
    VerifyEpochChange(SphinxProof),
    Groth16ProveInclusion(InclusionData),
    Groth16ProveEpochChange(EpochChangeData),
    Groth16VerifyInclusion(SphinxGroth16Proof),
    Groth16VerifyEpochChange(SphinxGroth16Proof),
}

impl Display for &Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::ProveInclusion(_) => write!(f, "ProveInclusion"),
            Request::ProveEpochChange(_) => write!(f, "ProveEpochChange"),
            Request::VerifyInclusion(_) => write!(f, "VerifyInclusion"),
            Request::VerifyEpochChange(_) => write!(f, "VerifyEpochChange"),
            Request::Groth16ProveInclusion(_) => write!(f, "Groth16ProveInclusion"),
            Request::Groth16ProveEpochChange(_) => write!(f, "Groth16ProveEpochChange"),
            Request::Groth16VerifyInclusion(_) => write!(f, "Groth16VerifyInclusion"),
            Request::Groth16VerifyEpochChange(_) => write!(f, "Groth16VerifyEpochChange"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum SecondaryRequest {
    Prove(EpochChangeData),
    Verify(SphinxProof),
    Groth16Prove(EpochChangeData),
    Groth16Verify(SphinxGroth16Proof),
}