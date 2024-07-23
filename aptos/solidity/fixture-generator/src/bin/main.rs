use clap::Parser;
use serde::{Deserialize, Serialize};
use sphinx_prover::types::HashableKey;
use sphinx_sdk::ProverClient;
use std::path::PathBuf;

pub const INCLUSION_ELF: &[u8] =
    include_bytes!("../../../../aptos-programs/artifacts/inclusion-program");
pub const EPOCH_CHANGE_ELF: &[u8] =
    include_bytes!("../../../../aptos-programs/artifacts/epoch-change-program");

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
    type_args: [String; 2],
    args: [MoveArg; 3],
}

fn generate_fixture_inclusion_aptos_lc() {
    tracing::info!("Generating inclusion fixture using Aptos program (for Solidity verification)");

    let elf = INCLUSION_ELF;
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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/plonk_fixtures");

    // save fixture
    let fixture = SolidityFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof.bytes(),
    };
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    let fixture_path = fixture_path.join("inclusion_fixture.json");
    std::fs::write(
        fixture_path.clone(),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    tracing::info!("Fixture has been successfully saved to {:?}", fixture_path);
}

fn generate_fixture_inclusion_ethereum_lc() {
    /*
        // save fixture
            let fixture = MoveFixture {
                type_args: [String::from("0x1::account::Account"), String::from("0x1::chain_id::ChainId")],
                args: [
                    MoveArg {
                        type_: String::from("hex"),
                        value: String::from("0x11111111")
                    },
                    MoveArg {
                        type_: String::from("hex"),
                        value: String::from("0x11111111")
                    },
                    MoveArg {
                        type_: String::from("hex"),
                        value: String::from("0x11111111")
                    },
                ]
            };
            std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
            let fixture_path = fixture_path.join(args.program.as_str().to_owned() + "_fixture.json");
            std::fs::write(
                fixture_path.clone(),
                serde_json::to_string_pretty(&fixture).unwrap(),
            ).expect("failed to write fixture");
    */
    unimplemented!();
}

fn generate_fixture_epoch_change_aptos_lc() {
    tracing::info!(
        "Generating epoch_change fixture using Aptos program (for Solidity verification)"
    );

    let elf = EPOCH_CHANGE_ELF;
    let (trusted_state, epoch_change_proof, _) = aptos_lc::epoch_change::setup_assets();
    let stdin = aptos_lc::epoch_change::generate_stdin(&trusted_state, &epoch_change_proof);

    let prover = ProverClient::new();
    let (pk, vk) = prover.setup(elf);
    let proof = prover.prove_plonk(&pk, stdin).unwrap();
    // just to check that proof is valid and verifiable
    prover.verify_plonk(&proof, &vk).unwrap();

    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/plonk_fixtures");

    // save fixture
    let fixture = SolidityFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof.bytes(),
    };
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    let fixture_path = fixture_path.join("inclusion_fixture.json");
    std::fs::write(
        fixture_path.clone(),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    tracing::info!("Fixture has been successfully saved to {:?}", fixture_path);
}

fn generate_fixture_epoch_change_ethereum_lc() {
    /*
        // save fixture
            let fixture = MoveFixture {
                type_args: [String::from("0x1::account::Account"), String::from("0x1::chain_id::ChainId")],
                args: [
                    MoveArg {
                        type_: String::from("hex"),
                        value: String::from("0x11111111")
                    },
                    MoveArg {
                        type_: String::from("hex"),
                        value: String::from("0x11111111")
                    },
                    MoveArg {
                        type_: String::from("hex"),
                        value: String::from("0x11111111")
                    },
                ]
            };
            std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
            let fixture_path = fixture_path.join(args.program.as_str().to_owned() + "_fixture.json");
            std::fs::write(
                fixture_path.clone(),
                serde_json::to_string_pretty(&fixture).unwrap(),
            ).expect("failed to write fixture");
    */
    unimplemented!();
}

fn main() {
    sphinx_sdk::utils::setup_logger();
    let args = ProveArgs::parse();

    match args.program.as_str() {
        "inclusion" => match args.language.as_str() {
            "solidity" => {
                generate_fixture_inclusion_aptos_lc();
            }
            "move" => {
                generate_fixture_inclusion_ethereum_lc();
            }
            _ => panic!("Unsupported language. Use: ['solidity', 'move']"),
        },
        "epoch_change" => match args.language.as_str() {
            "solidity" => {
                generate_fixture_epoch_change_aptos_lc();
            }
            "move" => {
                generate_fixture_epoch_change_ethereum_lc();
            }
            _ => panic!("Unsupported language. Use: ['solidity', 'move']"),
        },
        _ => panic!("Unsupported program. Use: ['inclusion', 'epoch_change']"),
    }
}
