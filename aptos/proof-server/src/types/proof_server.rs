// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use serde::{Deserialize, Serialize};
use sphinx_sdk::{SphinxPlonkBn254Proof, SphinxProof};
use std::fmt::Display;

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
    ProveInclusion(InclusionData),
    ProveEpochChange(EpochChangeData),
    VerifyInclusion(SphinxProof),
    VerifyEpochChange(SphinxProof),
    SnarkProveInclusion(InclusionData),
    SnarkProveEpochChange(EpochChangeData),
    SnarkVerifyInclusion(SphinxPlonkBn254Proof),
    SnarkVerifyEpochChange(SphinxPlonkBn254Proof),
}

impl Display for &Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::ProveInclusion(_) => write!(f, "ProveInclusion"),
            Request::ProveEpochChange(_) => write!(f, "ProveEpochChange"),
            Request::VerifyInclusion(_) => write!(f, "VerifyInclusion"),
            Request::VerifyEpochChange(_) => write!(f, "VerifyEpochChange"),
            Request::SnarkProveInclusion(_) => write!(f, "SnarkProveInclusion"),
            Request::SnarkProveEpochChange(_) => write!(f, "SnarkProveEpochChange"),
            Request::SnarkVerifyInclusion(_) => write!(f, "SnarkVerifyInclusion"),
            Request::SnarkVerifyEpochChange(_) => write!(f, "SnarkVerifyEpochChange"),
        }
    }
}

/// Secondary request type for the proof server. It is used to convey request from the primary
/// server to the secondary one.
#[derive(Serialize, Deserialize)]
pub enum SecondaryRequest {
    Prove(EpochChangeData),
    Verify(SphinxProof),
    SnarkProve(EpochChangeData),
    SnarkVerify(SphinxPlonkBn254Proof),
}
