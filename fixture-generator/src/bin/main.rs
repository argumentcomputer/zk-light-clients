use clap::Parser;
use serde::{Deserialize, Serialize};
use sphinx_prover::types::HashableKey;
use sphinx_sdk::ProverClient;
use std::path::PathBuf;

/// Location for the Inclusion program of the Aptos Light Client.
pub const APTOS_INCLUSION_ELF: &[u8] =
    include_bytes!("../../../aptos/aptos-programs/artifacts/inclusion-program");

/// Location for the Epoch Change program of the Aptos Light Client.
pub const APTOS_EPOCH_CHANGE_ELF: &[u8] =
    include_bytes!("../../../aptos/aptos-programs/artifacts/epoch-change-program");

/// Path to the directory where the Solidity fixtures for the Aptos Light Client are stored.
pub const SOLIDITY_FIXTURE_PATH: &str =
    "../aptos/solidity/contracts/src/plonk_fixtures";

/// Filename for the inclusion fixture.
pub const INCLUSION_FIXTURE_FILENAME: &str = "inclusion_fixture.json";

/// Filename for the epoch change fixture.
pub const EPOCH_CHANGE_FIXTURE_FILENAME: &str = "epoch_change_fixture.json";

/// Supported languages for the smart contracts, used for the Aptos Light Client.
pub const SOLIDITY: &str ="solidity";

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
    let proof = prover.prove_plonk(&pk, stdin).unwrap();
    // just to check that proof is valid and verifiable
    prover.verify_plonk(&proof, &vk).unwrap();

    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = SolidityFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof.bytes(),
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

fn generate_fixture_epoch_change_aptos_lc() {
    tracing::info!(
        "Generating epoch_change fixture using Aptos program (for Solidity verification)"
    );

    let elf = APTOS_EPOCH_CHANGE_ELF;
    let (trusted_state, epoch_change_proof, _) = aptos_lc::epoch_change::setup_assets();
    let stdin = aptos_lc::epoch_change::generate_stdin(&trusted_state, &epoch_change_proof);

    let prover = ProverClient::new();
    let (pk, vk) = prover.setup(elf);
    let proof = prover.prove_plonk(&pk, stdin).unwrap();
    // just to check that proof is valid and verifiable
    prover.verify_plonk(&proof, &vk).unwrap();

    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = SolidityFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof.bytes(),
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

fn main() {
    sphinx_sdk::utils::setup_logger();
    let args = ProveArgs::parse();

    match args.program.as_str() {
        INCLUSION=> match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_inclusion_aptos_lc();
            }
            _ => panic!("Unsupported language. Use: ['solidity']"),
        },
        EPOCH_CHANGE => match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_epoch_change_aptos_lc();
            }
            _ => panic!("Unsupported language. Use: ['solidity']"),
        },
        _ => panic!("Unsupported program. Use: ['inclusion', 'epoch_change']"),
    }
}
