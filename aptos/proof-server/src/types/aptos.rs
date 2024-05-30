// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::types::proof_server::{EpochChangeData, InclusionData};
use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use aptos_lc_core::crypto::hash::HashValue;
use aptos_lc_core::merkle::sparse_proof::SparseMerkleProof;
use aptos_lc_core::merkle::transaction_proof::TransactionAccumulatorProof;
use aptos_lc_core::types::ledger_info::LedgerInfoWithSignatures;
use aptos_lc_core::types::transaction::TransactionInfo;
use aptos_lc_core::types::trusted_state::{EpochChangeProof, TrustedState};
use aptos_lc_core::types::validator::ValidatorVerifier;
use serde::{Deserialize, Serialize};

/// The role of the Aptos node the client connects to. Can be Validator or Full Node.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum NodeRole {
    Validator,
    FullNode,
}

/// This structure represents the expected payload received from the Aptos node endpoint `/v1/`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LedgerInfoResponse {
    chain_id: u8,
    epoch: String,
    ledger_version: String,
    oldest_ledger_version: String,
    ledger_timestamp: String,
    node_role: NodeRole,
    oldest_block_height: String,
    block_height: String,
}

impl LedgerInfoResponse {
    pub fn epoch(&self) -> String {
        self.epoch.clone()
    }
}

/// This structure represents the expected payload received from the Aptos node endpoint `/v1/epoch/proof`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EpochChangeProofResponse {
    epoch_change_proof: EpochChangeProof,
    trusted_state: TrustedState,
}

impl EpochChangeProofResponse {
    pub const fn epoch_change_proof(&self) -> &EpochChangeProof {
        &self.epoch_change_proof
    }
    pub const fn trusted_state(&self) -> &TrustedState {
        &self.trusted_state
    }
}

impl From<EpochChangeProofResponse> for EpochChangeData {
    fn from(val: EpochChangeProofResponse) -> Self {
        EpochChangeData {
            epoch_change_proof: val.epoch_change_proof.to_bytes(),
            trusted_state: val.trusted_state.to_bytes(),
        }
    }
}

/// This structure represents the expected payload received
/// from the Aptos node endpoint `/v1/accounts/:address/proof`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountInclusionProofResponse {
    /// Proof for the account inclusion
    state_proof: SparseMerkleProof,
    /// Account leaf key
    element_key: HashValue,
    /// Account state value
    element_hash: HashValue,
    /// Proof for the transaction inclusion
    transaction_proof: TransactionAccumulatorProof,
    /// Hashed representation of the transaction
    transaction: TransactionInfo,
    /// Signed Ledger info with the transaction
    ledger_info_v0: LedgerInfoWithSignatures,
    /// ValidatorVerifier valid for the proof
    validator_verifier: ValidatorVerifier,
}

impl From<AccountInclusionProofResponse> for InclusionData {
    fn from(val: AccountInclusionProofResponse) -> Self {
        InclusionData {
            sparse_merkle_proof_assets: SparseMerkleProofAssets::new(
                val.state_proof.to_bytes(),
                *val.element_key.as_ref(),
                *val.element_hash.as_ref(),
            ),
            transaction_proof_assets: TransactionProofAssets::new(
                val.transaction.to_bytes(),
                val.ledger_info_v0.ledger_info().version(),
                val.transaction_proof.to_bytes(),
                val.ledger_info_v0.to_bytes(),
            ),
            validator_verifier_assets: ValidatorVerifierAssets::new(
                val.validator_verifier.to_bytes(),
            ),
        }
    }
}
