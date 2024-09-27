use clap::Parser;
use serde::{Deserialize, Serialize};
use sphinx_prover::types::HashableKey;
use sphinx_sdk::{ProverClient, SphinxProof, SphinxProofWithPublicValues};
use std::fmt::Display;
use std::path::PathBuf;

use ethereum_lc::proofs::committee_change::{CommitteeChangeIn, CommitteeChangeProver};
use ethereum_lc::proofs::inclusion::{StorageInclusionIn, StorageInclusionProver};
use ethereum_lc::proofs::{ProofType, Prover, ProvingMode};
use ethereum_lc::test_utils::{
    generate_committee_change_test_assets, generate_inclusion_test_assets,
};

use kadena_lc::proofs::longest_chain::{LongestChainIn, LongestChainProver};
use kadena_lc::proofs::spv::{SpvIn, SpvProver};
use kadena_lc::proofs::{
    ProofType as KadenaProofType, Prover as KadenaProver, ProvingMode as KadenaProvingMode,
};
use kadena_lc::test_utils::{get_layer_block_headers, get_test_assets};

/// Location for the Inclusion program of the Aptos Light Client.
pub const APTOS_INCLUSION_ELF: &[u8] =
    include_bytes!("../../../aptos/aptos-programs/artifacts/inclusion-program");

/// Location for the Epoch Change program of the Aptos Light Client.
pub const APTOS_EPOCH_CHANGE_ELF: &[u8] =
    include_bytes!("../../../aptos/aptos-programs/artifacts/epoch-change-program");

/// Location for the Longest-Chain program of the Kadena-Ethereum Light Client.
pub const KADENA_LONGEST_CHAIN_ELF: &[u8] =
    include_bytes!("../../../kadena/kadena-programs/artifacts/longest-chain-program");

/// Location for the SPV program of the Kadena-Ethereum Light Client.
pub const KADENA_SPV_ELF: &[u8] =
    include_bytes!("../../../kadena/kadena-programs/artifacts/spv-program");

/// Path to the directory where the Solidity fixtures for the Aptos Light Client are stored.
pub const APTOS_SOLIDITY_FIXTURE_PATH: &str = "../aptos/solidity/contracts/src/plonk_fixtures";

/// Path to the directory where the Solidity fixtures for the Aptos Light Client are stored.
pub const KADENA_SOLIDITY_FIXTURE_PATH: &str = "../kadena/solidity/contracts/src/plonk_fixtures";

/// Path to the directory where the Move fixtures for the Ethereum Light Client are stored.
pub const MOVE_FIXTURE_PATH: &str = "../ethereum/move/sources/fixtures";

/// Path to the directory where the Pact fixtures for the Ethereum Light Client are stored.
pub const PACT_FIXTURE_PATH: &str = "../ethereum/pact/fixtures";

/// Filename for the longest_chain fixture.
pub const LONGEST_CHAIN_FIXTURE_FILENAME: &str = "longest_chain_fixture.json";

/// Filename for the spv fixture.
pub const SPV_FIXTURE_FILENAME: &str = "spv_fixture.json";

/// Filename for the inclusion fixture.
pub const INCLUSION_FIXTURE_FILENAME: &str = "inclusion_fixture.json";

/// Filename for the epoch change fixture.
pub const EPOCH_CHANGE_FIXTURE_FILENAME: &str = "epoch_change_fixture.json";

/// Supported languages for the smart contracts, used for the Aptos Light Client.
pub const SOLIDITY: &str = "solidity";

/// Supported languages for the smart contracts, used for the Ethereum Light Client.
pub const MOVE: &str = "move";

/// Supported languages for the smart contracts, used for the Ethereum Light Client.
pub const PACT: &str = "pact";

/// Supported programs for the fixtures.
pub const INCLUSION: &str = "inclusion";

/// Supported programs for the fixtures.
pub const EPOCH_CHANGE: &str = "epoch_change";

/// Supported programs for the fixtures.
pub const LONGEST_CHAIN: &str = "longest_chain";

/// Supported programs for the fixtures.
pub const SPV: &str = "spv";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProveArgs {
    #[clap(long, default_value_t = String::from("inclusion"))]
    program: String,
    #[clap(long, default_value_t = String::from("solidity"))]
    language: String,
}

/// Contains all types of fixtures assets that might be needed to
/// test our verifiers.
enum Fixture {
    Base(BaseFixture),
    Move(MoveFixture),
}

impl Display for Fixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fixture::Base(fixture) => serde_json::to_string_pretty(fixture).unwrap().fmt(f),
            Fixture::Move(fixture) => serde_json::to_string_pretty(fixture).unwrap().fmt(f),
        }
    }
}

/// Base fixtures format. Currently used for PACT and Solidity verifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BaseFixture {
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

/// Move fixtures format. Currently used for Move verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveFixture {
    type_args: [String; 2], // two hardcoded service fields required by Aptos
    args: [MoveArg; 3],     // vk, public_values, proof
}

/// Converts the encoded proof to a string.
fn proof_bytes(proof: &SphinxProofWithPublicValues) -> String {
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

/// Converts the raw proof to a string.
fn raw_proof_bytes(proof: &SphinxProofWithPublicValues) -> String {
    match &proof.proof {
        SphinxProof::Plonk(pr) => {
            format!(
                "0x{}",       // no vkey prefix
                pr.raw_proof, // not encoded_proof
            )
        }
        _ => unimplemented!("Only Plonk proofs are supported for now"),
    }
}

/// Saves the fixture to a file.
fn save_fixture(fixture: &Fixture, fixture_path: &PathBuf, fixture_file_name: &str) {
    std::fs::create_dir_all(fixture_path).expect("failed to create fixture path");
    let fixture_path = fixture_path.join(fixture_file_name);
    std::fs::write(fixture_path.clone(), fixture.to_string()).expect("failed to write fixture");

    tracing::info!("Fixture has been successfully saved to {:?}", fixture_path);
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

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(APTOS_SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = BaseFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof_bytes(&proof),
    };

    save_fixture(
        &Fixture::Base(fixture),
        &fixture_path,
        INCLUSION_FIXTURE_FILENAME,
    );
}

fn generate_fixture_inclusion_ethereum_lc(remote: &str) {
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

    match remote {
        MOVE => {
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
                        value: proof_bytes(&proof),
                    },
                ],
            };

            let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MOVE_FIXTURE_PATH);

            save_fixture(
                &Fixture::Move(fixture),
                &fixture_path,
                INCLUSION_FIXTURE_FILENAME,
            );
        }
        PACT => {
            let fixture = BaseFixture {
                vkey: prover.get_vk().bytes32().to_string(),
                public_values: proof.public_values.bytes().to_string(),
                proof: raw_proof_bytes(&proof),
            };

            let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PACT_FIXTURE_PATH);

            save_fixture(
                &Fixture::Base(fixture),
                &fixture_path,
                INCLUSION_FIXTURE_FILENAME,
            );
        }
        _ => panic!("Unsupported language. Use: ['move', 'pact']"),
    };
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

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(APTOS_SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = BaseFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof_bytes(&proof),
    };

    save_fixture(
        &Fixture::Base(fixture),
        &fixture_path,
        EPOCH_CHANGE_FIXTURE_FILENAME,
    );
}

fn generate_fixture_epoch_change_ethereum_lc(remote: &str) {
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

    match remote {
        MOVE => {
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
                        value: proof_bytes(&proof),
                    },
                ],
            };

            let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MOVE_FIXTURE_PATH);

            save_fixture(
                &Fixture::Move(fixture),
                &fixture_path,
                EPOCH_CHANGE_FIXTURE_FILENAME,
            );
        }
        PACT => {
            let fixture = BaseFixture {
                vkey: prover.get_vk().bytes32().to_string(),
                public_values: proof.public_values.bytes().to_string(),
                proof: raw_proof_bytes(&proof),
            };

            let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PACT_FIXTURE_PATH);

            save_fixture(
                &Fixture::Base(fixture),
                &fixture_path,
                EPOCH_CHANGE_FIXTURE_FILENAME,
            );
        }
        _ => panic!("Unsupported language. Use: ['move', 'pact']"),
    };
}

fn generate_fixture_longest_chain() {
    tracing::info!(
        "Generating longest_chain fixture using Kadena program (for Solidity verification)"
    );

    let layer_block_headers = get_layer_block_headers();
    let prover = LongestChainProver::new();
    let input = LongestChainIn::new(layer_block_headers);

    let proof = match prover.prove(&input, KadenaProvingMode::SNARK).unwrap() {
        KadenaProofType::SNARK(inner_proof) => inner_proof,
        _ => {
            panic!("Unexpected proof")
        }
    };
    prover
        .verify(&KadenaProofType::SNARK(proof.clone()))
        .unwrap();

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(KADENA_SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = BaseFixture {
        vkey: prover.get_vk().bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof_bytes(&proof),
    };

    save_fixture(
        &Fixture::Base(fixture),
        &fixture_path,
        LONGEST_CHAIN_FIXTURE_FILENAME,
    );
}

fn generate_fixture_spv() {
    tracing::info!("Generating spv fixture using Kadena program (for Solidity verification)");

    let test_assets = get_test_assets();
    let prover = SpvProver::new();
    let input = SpvIn::new(
        test_assets.layer_headers().clone(),
        test_assets.spv().clone(),
        *test_assets.expected_root(),
    );

    let proof = match prover.prove(&input, KadenaProvingMode::SNARK).unwrap() {
        KadenaProofType::SNARK(inner_proof) => inner_proof,
        _ => {
            panic!("Unexpected proof")
        }
    };
    prover
        .verify(&KadenaProofType::SNARK(proof.clone()))
        .unwrap();

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(KADENA_SOLIDITY_FIXTURE_PATH);

    // save fixture
    let fixture = BaseFixture {
        vkey: prover.get_vk().bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof_bytes(&proof),
    };

    save_fixture(&Fixture::Base(fixture), &fixture_path, SPV_FIXTURE_FILENAME);
}

fn main() {
    sphinx_sdk::utils::setup_logger();
    let args = ProveArgs::parse();

    match args.program.as_str() {
        INCLUSION => match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_inclusion_aptos_lc();
            }
            MOVE | PACT => {
                generate_fixture_inclusion_ethereum_lc(args.language.as_str());
            }
            _ => panic!("Unsupported language. Use: ['solidity', 'move']"),
        },
        EPOCH_CHANGE => match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_epoch_change_aptos_lc();
            }
            MOVE | PACT => {
                generate_fixture_epoch_change_ethereum_lc(args.language.as_str());
            }
            _ => panic!("Unsupported language. Use: ['solidity', 'move']"),
        },
        LONGEST_CHAIN => match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_longest_chain();
            }
            _ => panic!("Unsupported language"),
        },
        SPV => match args.language.as_str() {
            SOLIDITY => {
                generate_fixture_spv();
            }
            _ => panic!("Unsupported language"),
        },
        _ => panic!(
            "Unsupported program. Use: ['inclusion', 'epoch_change', 'longest_chain', 'spv']"
        ),
    }
}
