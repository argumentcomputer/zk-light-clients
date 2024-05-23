use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RatchetingProofRequest {
    pub trusted_state: Vec<u8>,
    pub epoch_change_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct MerkleInclusionProofRequest {
    pub sparse_merkle_proof_assets: SparseMerkleProofAssets,
    pub transaction_proof_assets: TransactionProofAssets,
    pub validator_verifier_assets: ValidatorVerifierAssets,
}
