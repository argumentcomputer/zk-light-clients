use clap::Parser;
use serde::{Deserialize, Serialize};
use sphinx_prover::types::HashableKey;
use sphinx_sdk::{ProverClient, SphinxProof, SphinxProofWithPublicValues};
use std::path::PathBuf;

use ethereum_lc::proofs::committee_change::{CommitteeChangeIn, CommitteeChangeProver};
use ethereum_lc::proofs::inclusion::{StorageInclusionIn, StorageInclusionProver};
use ethereum_lc::proofs::{ProofType, Prover, ProvingMode};
use ethereum_lc::test_utils::{
    generate_committee_change_test_assets, generate_inclusion_test_assets,
};

/// Location for the Inclusion program of the Aptos Light Client.
pub const APTOS_INCLUSION_ELF: &[u8] =
    include_bytes!("../../../aptos/aptos-programs/artifacts/inclusion-program");

/// Location for the Epoch Change program of the Aptos Light Client.
pub const APTOS_EPOCH_CHANGE_ELF: &[u8] =
    include_bytes!("../../../aptos/aptos-programs/artifacts/epoch-change-program");

/// Path to the directory where the Solidity fixtures for the Aptos Light Client are stored.
pub const SOLIDITY_FIXTURE_PATH: &str = "../aptos/solidity/contracts/src/plonk_fixtures";

/// Path to the directory where the Move fixtures for the Ethereum Light Client are stored.
pub const MOVE_FIXTURE_PATH: &str = "../ethereum/move/sources/fixtures";

/// Filename for the inclusion fixture.
pub const INCLUSION_FIXTURE_FILENAME: &str = "inclusion_fixture.json";

/// Filename for the epoch change fixture.
pub const EPOCH_CHANGE_FIXTURE_FILENAME: &str = "epoch_change_fixture.json";

/// Supported languages for the smart contracts, used for the Aptos Light Client.
pub const SOLIDITY: &str = "solidity";

/// Supported languages for the smart contracts, used for the Ethereum Light Client.
pub const MOVE: &str = "move";

/// Supported programs for the fixtures.
pub const INCLUSION: &str = "inclusion";

/// Supported programs for the fixtures.
pub const EPOCH_CHANGE: &str = "epoch_change";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value_t = String::from("inclusion"))]
    program: String,
    #[clap(long, default_value_t = String::from("solidity"))]
    language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SolidityFixture {
    vkey: String,
    public_values: String,
    proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveArg {
    #[serde(rename = "type")]
    type_: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveFixture {
    type_args: [String; 2], // two hardcoded service fields required by Aptos
    args: [MoveArg; 3],     // vk, public_values, proof
}

fn bytes(proof: &SphinxProofWithPublicValues) -> String {
    match &proof.proof {
        SphinxProof::Plonk(pr) => {
            format!(
                "0x{}{}",
                hex::encode(&pr.plonk_vkey_hash[..4]),
                pr.encoded_proof,
            )
        }
        _ => unimplemented!("Only Plonk proofs are supported for now"),
    }
}

fn generate_fixture_inclusion_aptos_lc() {
    tracing::info!("Generating inclusion fixture using Aptos program (for Solidity verification)");

    let elf = APTOS_INCLUSION_ELF;
    let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
        aptos_lc::inclusion::setup_assets();
    let stdin = aptos_lc::inclusion::generate_stdin(
        &sparse_merkle_proof_assets,
        &transaction_proof_assets,
        &validator_verifier_assets,
    );

    let prover = ProverClient::new();
    let (pk, vk) = prover.setup(elf);
    let proof = prover.prove(&pk, stdin).plonk().run().unwrap();
    // just to check that proof is valid and verifiable
    prover.verify(&proof, &vk).unwrap();

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = SolidityFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: bytes(&proof),
    };
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    let fixture_path = fixture_path.join(INCLUSION_FIXTURE_FILENAME);
    std::fs::write(
        fixture_path.clone(),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    tracing::info!("Fixture has been successfully saved to {:?}", fixture_path);
}

fn generate_fixture_inclusion_ethereum_lc() {
    tracing::info!("Generating inclusion fixture using Ethereum program (for Move verification)");

    let prover = StorageInclusionProver::new();
    let test_assets = generate_inclusion_test_assets();
    let input = StorageInclusionIn::new(
        test_assets.store().clone(),
        test_assets.finality_update().clone().into(),
        test_assets.eip1186_proof().clone(),
    );
    let proof = match prover.prove(&input, ProvingMode::SNARK).unwrap() {
        ProofType::SNARK(inner_proof) => inner_proof,
        _ => {
            panic!("Unexpected proof")
        }
    };
    prover.verify(&ProofType::SNARK(proof.clone())).unwrap();

    // save fixture
    let fixture = MoveFixture {
        type_args: [
            String::from("0x1::account::Account"),
            String::from("0x1::chain_id::ChainId"),
        ],
        args: [
            MoveArg {
                // vk
                type_: String::from("hex"),
                value: prover.get_vk().bytes32().to_string(),
            },
            MoveArg {
                // public values
                type_: String::from("hex"),
                value: proof.public_values.bytes().to_string(),
            },
            MoveArg {
                // proof
                type_: String::from("hex"),
                value: bytes(&proof),
            },
        ],
    };

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MOVE_FIXTURE_PATH);
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    let fixture_path = fixture_path.join(INCLUSION_FIXTURE_FILENAME);
    std::fs::write(
        fixture_path.clone(),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    tracing::info!("Fixture has been successfully saved to {:?}", fixture_path);
}

fn generate_fixture_epoch_change_aptos_lc() {
    tracing::info!(
        "Generating epoch_change fixture using Aptos program (for Solidity verification)"
    );

    let elf = APTOS_EPOCH_CHANGE_ELF;
    let (trusted_state, epoch_change_proof, _) = aptos_lc::epoch_change::setup_assets();
    let stdin = aptos_lc::epoch_change::generate_stdin(&trusted_state, &epoch_change_proof);

    let prover = ProverClient::new();
    let (pk, vk) = prover.setup(elf);
    let proof = prover.prove(&pk, stdin).plonk().run().unwrap();
    // just to check that proof is valid and verifiable
    prover.verify(&proof, &vk).unwrap();

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = SolidityFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: bytes(&proof),
    };
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    let fixture_path = fixture_path.join(EPOCH_CHANGE_FIXTURE_FILENAME);
    std::fs::write(
        fixture_path.clone(),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    tracing::info!("Fixture has been successfully saved to {:?}", fixture_path);
}

fn generate_fixture_epoch_change_ethereum_lc() {
    tracing::info!(
        "Generating epoch_change fixture using Ethereum program (for Move verification)"
    );

    let mut test_assets = generate_committee_change_test_assets();
    test_assets
        .store
        .process_light_client_update(&test_assets.update)
        .unwrap();
    let new_period_inputs =
        CommitteeChangeIn::new(test_assets.store, test_assets.update_new_period);
    let prover = CommitteeChangeProver::new();
    let proof = match prover
        .prove(&new_period_inputs, ProvingMode::SNARK)
        .unwrap()
    {
        ProofType::SNARK(inner_proof) => inner_proof,
        _ => {
            panic!("Unexpected proof")
        }
    };
    prover.verify(&ProofType::SNARK(proof.clone())).unwrap();

    // save fixture
    let fixture = MoveFixture {
        type_args: [
            String::from("0x1::account::Account"),
            String::from("0x1::chain_id::ChainId"),
        ],
        args: [
            MoveArg {
                // vk
                type_: String::from("hex"),
                value: prover.get_vk().bytes32().to_string(),
            },
            MoveArg {
                // public values
                type_: String::from("hex"),
                value: proof.public_values.bytes().to_string(),
            },
            MoveArg {
                // proof
                type_: String::from("hex"),
                value: bytes(&proof),
            },
        ],
    };

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MOVE_FIXTURE_PATH);

    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    let fixture_path = fixture_path.join(EPOCH_CHANGE_FIXTURE_FILENAME);
    std::fs::write(
        fixture_path.clone(),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    tracing::info!("Fixture has been successfully saved to {:?}", fixture_path);
}

fn main() {
    sphinx_sdk::utils::setup_logger();
    let args = ProveArgs::parse();

    match args.program.as_str() {
        INCLUSION => match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_inclusion_aptos_lc();
            }
            MOVE => {
                generate_fixture_inclusion_ethereum_lc();
            }
            _ => panic!("Unsupported language. Use: ['solidity', 'move']"),
        },
        EPOCH_CHANGE => match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_epoch_change_aptos_lc();
            }
            MOVE => {
                generate_fixture_epoch_change_ethereum_lc();
            }
            _ => panic!("Unsupported language. Use: ['solidity', 'move']"),
        },
        _ => panic!("Unsupported program. Use: ['inclusion', 'epoch_change']"),
    }
}
