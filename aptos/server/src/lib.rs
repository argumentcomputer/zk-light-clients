use aptos_lc::merkle::{SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RatchetRequest {
    pub trusted_state: Vec<u8>,
    pub epoch_change_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct MerkleRequest {
    pub sparse_merkle_proof_assets: SparseMerkleProofAssets,
    pub transaction_proof_assets: TransactionProofAssets,
    pub validator_verifier_assets: ValidatorVerifierAssets,
}
