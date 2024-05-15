use anyhow::{anyhow, Result};
use aptos_lc::{merkle, ratchet};
use wp1_sdk::{ProverClient, SP1DefaultProof};

use server::{MerkleRequest, RatchetRequest};

#[tonic_rpc::tonic_rpc(bincode)]
trait Aptos {
    fn ratchet(request: RatchetRequest) -> SP1DefaultProof;
    fn merkle(request: MerkleRequest) -> SP1DefaultProof;
}

struct Server;

#[tonic::async_trait]
impl aptos_server::Aptos for Server {
    async fn ratchet(
        &self,
        request: tonic::Request<RatchetRequest>,
    ) -> Result<tonic::Response<SP1DefaultProof>, tonic::Status> {
        let RatchetRequest {
            trusted_state,
            epoch_change_proof,
        } = request.into_inner();

        let proof =
            ratchet::generate_proof(&ProverClient::new(), &trusted_state, &epoch_change_proof)
                .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(proof))
    }

    async fn merkle(
        &self,
        request: tonic::Request<MerkleRequest>,
    ) -> Result<tonic::Response<SP1DefaultProof>, tonic::Status> {
        let MerkleRequest {
            sparse_merkle_proof_assets,
            transaction_proof_assets,
            validator_verifier_assets,
        } = request.into_inner();

        let proof = merkle::generate_proof(
            &ProverClient::new(),
            &sparse_merkle_proof_assets,
            &transaction_proof_assets,
            &validator_verifier_assets,
        )
        .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(proof))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let port: u16 = std::env::args()
        .collect::<Vec<_>>()
        .get(1)
        .ok_or(anyhow!("Missing port argument"))?
        .parse()?;

    let addr = format!("[::1]:{port}").parse()?;

    tonic::transport::Server::builder()
        .add_service(aptos_server::AptosServer::new(Server))
        .serve(addr)
        .await?;
    Ok(())
}
