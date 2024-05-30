// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use wp1_sdk::SP1Proof;

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
    VerifyInclusion(SP1Proof),
    VerifyEpochChange(SP1Proof),
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

#[derive(Serialize, Deserialize)]
pub enum SecondaryRequest {
    Prove(EpochChangeData),
    Verify(SP1Proof),
}
