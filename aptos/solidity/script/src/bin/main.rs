use clap::Parser;
use serde::{Deserialize, Serialize};
use sphinx_prover::types::HashableKey;
use sphinx_prover::SphinxStdin;
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ProofFixture {
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    sphinx_sdk::utils::setup_logger();
    let args = ProveArgs::parse();

    let elf: &[u8];
    let stdin: SphinxStdin;
    match args.program.as_str() {
        "inclusion" => {
            elf = INCLUSION_ELF;
            let (sparse_merkle_proof_assets, transaction_proof_assets, validator_verifier_assets) =
                aptos_lc::inclusion::setup_assets();
            stdin = aptos_lc::inclusion::generate_stdin(
                &sparse_merkle_proof_assets,
                &transaction_proof_assets,
                &validator_verifier_assets,
            );
        }
        "epoch_change" => {
            elf = EPOCH_CHANGE_ELF;
            let (trusted_state, epoch_change_proof) = aptos_lc::epoch_change::setup_assets();
            stdin = aptos_lc::epoch_change::generate_stdin(&trusted_state, &epoch_change_proof);
        }
        _ => panic!("Unsupported program. Use: ['inclusion', 'epoch_change']"),
    }

    let prover = ProverClient::new();
    let (pk, vk) = prover.setup(elf);
    let proof = prover.prove_plonk(&pk, stdin).unwrap();
    // just to check that proof is valid and verifiable
    prover.verify_plonk(&proof, &vk).unwrap();

    // save fixture
    let fixture = SP1ProofFixture {
        vkey: vk.bytes32().to_string(),
        public_values: proof.public_values.bytes().to_string(),
        proof: proof.bytes(),
    };

    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/plonk_fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(args.program.as_str().to_owned() + "_fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
