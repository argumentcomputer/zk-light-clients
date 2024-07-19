use ethers_core::types::EIP1186ProofResponse;
use getset::Getters;
use serde::{Deserialize, Serialize};

/// The response from the `eth_getProof` RPC method.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize, Getters)]
pub struct GetProofResponse {
    id: u64,
    jsonrpc: String,
    #[getset(get = "pub")]
    result: EIP1186ProofResponse,
}
