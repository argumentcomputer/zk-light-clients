// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

use anyhow::Result;
use aptos_lc::{
    epoch_change, inclusion,
    inclusion::{SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets},
};
use aptos_lc_core::{aptos_test_utils::wrapper::AptosWrapper, types::trusted_state::TrustedState};
use clap::{Parser, Subcommand};
use proof_server::{read_bytes, write_bytes, EpochChangeData, InclusionData, Request};
use tokio::{io::AsyncReadExt, net::TcpStream};
use wp1_sdk::{ProverClient, SP1Proof};

/// A dummy client displaying how one can make requests to the proof server and
/// handle its responses.
///
/// It can request proof generation and verification for inclusions and epoch
/// changes using data from randomly generated traffic.
#[derive(Parser)]
struct Cli {
    /// The address of the proof server
    #[arg(long)]
    addr: String,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Requests an inclusion proof, verifies it locally and then on the server
    Inclusion,
    /// Requests an epoch change proof, verifies it locally and then on the server
    EpochChange,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { addr, cmd } = Cli::parse();

    let mut stream = TcpStream::connect(&addr).await?;

    const NBR_VALIDATORS: usize = 130;
    const AVERAGE_SIGNERS_NBR: usize = 95;

    match cmd {
        Command::Inclusion => {
            let mut aptos_wrapper = AptosWrapper::new(500, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR)?;
            aptos_wrapper.generate_traffic()?;

            let proof_assets = aptos_wrapper.get_latest_proof_account(400)?;

            let sparse_merkle_proof = bcs::to_bytes(proof_assets.state_proof())?;
            let key: [u8; 32] = *proof_assets.key().as_ref();
            let element_hash: [u8; 32] = *proof_assets.state_value_hash()?.as_ref();

            let transaction = bcs::to_bytes(&proof_assets.transaction())?;
            let transaction_proof = bcs::to_bytes(&proof_assets.transaction_proof())?;

            let latest_li = aptos_wrapper.get_latest_li_bytes()?;

            let validator_verifier =
                match TrustedState::from_bytes(&bcs::to_bytes(&aptos_wrapper.trusted_state())?)? {
                    TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().clone(),
                    _ => panic!("expected epoch state"),
                };

            let sparse_merkle_proof_assets =
                SparseMerkleProofAssets::new(sparse_merkle_proof, key, element_hash);

            let transaction_proof_assets = TransactionProofAssets::new(
                transaction,
                *proof_assets.transaction_version(),
                transaction_proof,
                latest_li,
            );

            let validator_verifier_assets =
                ValidatorVerifierAssets::new(validator_verifier.to_bytes());

            let request = Request::ProveInclusion(InclusionData {
                sparse_merkle_proof_assets,
                transaction_proof_assets,
                validator_verifier_assets,
            });
            let request_bytes = bcs::to_bytes(&request)?;

            write_bytes(&mut stream, &request_bytes).await?;
            let proof_bytes = read_bytes(&mut stream).await?;

            let proof: SP1Proof = bcs::from_bytes(&proof_bytes)?;
            let prover_client = ProverClient::default();
            let (_, vk) = inclusion::generate_keys(&prover_client);

            prover_client.verify(&proof, &vk)?;

            println!("Proof verified!");

            let request = Request::VerifyInclusion(proof);
            let request_bytes = bcs::to_bytes(&request)?;

            let mut stream = TcpStream::connect(&addr).await?;
            write_bytes(&mut stream, &request_bytes).await?;
            let verified = stream.read_u8().await?;
            assert_eq!(verified, 1);

            println!("Proof verified on the server!");
        }
        Command::EpochChange => {
            let mut aptos_wrapper = AptosWrapper::new(20000, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR)?;

            let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state())?;
            let trusted_state_version = *aptos_wrapper.current_version();

            aptos_wrapper.generate_traffic()?;

            let state_proof = aptos_wrapper.new_state_proof(trusted_state_version)?;

            let epoch_change_proof = bcs::to_bytes(state_proof.epoch_changes())?;

            let request = Request::ProveEpochChange(EpochChangeData {
                trusted_state,
                epoch_change_proof,
            });
            let request_bytes = bcs::to_bytes(&request)?;

            write_bytes(&mut stream, &request_bytes).await?;
            let proof_bytes = read_bytes(&mut stream).await?;

            let proof: SP1Proof = bcs::from_bytes(&proof_bytes)?;
            let prover_client = ProverClient::default();
            let (_, vk) = epoch_change::generate_keys(&prover_client);

            prover_client.verify(&proof, &vk)?;

            println!("Proof verified!");

            let request = Request::VerifyEpochChange(proof);
            let request_bytes = bcs::to_bytes(&request)?;

            let mut stream = TcpStream::connect(&addr).await?;
            write_bytes(&mut stream, &request_bytes).await?;
            let verified = stream.read_u8().await?;
            assert_eq!(verified, 1);

            println!("Proof verified on the server!");
        }
    }

    Ok(())
}
