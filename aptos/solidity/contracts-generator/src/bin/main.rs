use anyhow::Result;
use log::info;
use sphinx_sdk::artifacts::try_install_plonk_bn254_artifacts;
use sphinx_sdk::utils::setup_logger;
use std::path::PathBuf;

fn main() -> Result<()> {
    setup_logger();

    let artifacts_dir = try_install_plonk_bn254_artifacts();

    // Read all Solidity files from the artifacts_dir.
    let sol_files = std::fs::read_dir(artifacts_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("sol"))
        .collect::<Vec<_>>();

    // Write each Solidity file to the contracts directory.
    let contracts_src_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/plonk");

    for sol_file in sol_files {
        let sol_file_path = sol_file.path();
        let sol_file_contents = std::fs::read(&sol_file_path)?;
        std::fs::write(
            contracts_src_dir.join(sol_file_path.file_name().unwrap()),
            sol_file_contents,
        )?;
    }

    info!("Contracts have been installed to: {:?}", contracts_src_dir);

    Ok(())
}
