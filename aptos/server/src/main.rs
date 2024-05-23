use anyhow::{anyhow, Result};
use aptos_lc::{epoch_change, inclusion};
use wp1_sdk::{ProverClient, SP1Proof, SP1ProvingKey, SP1VerifyingKey};

use server::{MerkleInclusionProofRequest, RatchetingProofRequest};

#[tonic_rpc::tonic_rpc(bincode)]
trait Aptos {
    fn prove_ratcheting(request: RatchetingProofRequest) -> SP1Proof;
    fn prove_merkle_inclusion(request: MerkleInclusionProofRequest) -> SP1Proof;
    fn verify_ratcheting_proof(proof: SP1Proof) -> bool;
    fn verify_merkle_inclusion_proof(proof: SP1Proof) -> bool;
}

struct Server {
    prover_client: ProverClient,
    ratcheting_keys: (SP1ProvingKey, SP1VerifyingKey),
    merkle_inclusion_keys: (SP1ProvingKey, SP1VerifyingKey),
}

impl Default for Server {
    fn default() -> Self {
        let prover_client = ProverClient::default();
        let ratcheting_keys = epoch_change::generate_keys(&prover_client);
        let merkle_inclusion_keys = inclusion::generate_keys(&prover_client);
        Self {
            prover_client,
            ratcheting_keys,
            merkle_inclusion_keys,
        }
    }
}

#[tonic::async_trait]
impl aptos_server::Aptos for Server {
    async fn prove_ratcheting(
        &self,
        request: tonic::Request<RatchetingProofRequest>,
    ) -> Result<tonic::Response<SP1Proof>, tonic::Status> {
        let RatchetingProofRequest {
            trusted_state,
            epoch_change_proof,
        } = request.into_inner();

        let (pk, _) = &self.ratcheting_keys;
        let stdin = epoch_change::generate_stdin(&trusted_state, &epoch_change_proof);

        let proof = self
            .prover_client
            .prove(pk, stdin)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(proof))
    }

    async fn prove_merkle_inclusion(
        &self,
        request: tonic::Request<MerkleInclusionProofRequest>,
    ) -> Result<tonic::Response<SP1Proof>, tonic::Status> {
        let MerkleInclusionProofRequest {
            sparse_merkle_proof_assets,
            transaction_proof_assets,
            validator_verifier_assets,
        } = request.into_inner();

        let (pk, _) = &self.merkle_inclusion_keys;
        let stdin = inclusion::generate_stdin(
            &sparse_merkle_proof_assets,
            &transaction_proof_assets,
            &validator_verifier_assets,
        );

        let proof = self
            .prover_client
            .prove(pk, stdin)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(proof))
    }

    async fn verify_ratcheting_proof(
        &self,
        request: tonic::Request<SP1Proof>,
    ) -> Result<tonic::Response<bool>, tonic::Status> {
        let (_, vk) = &self.ratcheting_keys;
        let proof = request.into_inner();
        Ok(tonic::Response::new(
            self.prover_client.verify(&proof, vk).is_ok(),
        ))
    }

    async fn verify_merkle_inclusion_proof(
        &self,
        request: tonic::Request<SP1Proof>,
    ) -> Result<tonic::Response<bool>, tonic::Status> {
        let (_, vk) = &self.merkle_inclusion_keys;
        let proof = request.into_inner();
        Ok(tonic::Response::new(
            self.prover_client.verify(&proof, vk).is_ok(),
        ))
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
        .add_service(aptos_server::AptosServer::new(Server::default()))
        .serve(addr)
        .await?;
    Ok(())
}
