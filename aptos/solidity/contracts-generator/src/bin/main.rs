use anyhow::Result;
use home::home_dir;
use log::info;
use sphinx_sdk::utils::setup_logger;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    setup_logger();

    // This should be replaced with
    //
    // `sphinx_sdk::artifacts::try_install_plonk_bn254_artifacts`
    //
    // once we can make our AWS bucket public
    let artifacts_dir = download_artifacts_from_private_aws();

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

    info!(
        "[contracts-generator] Contracts have been installed to: {:?}",
        contracts_src_dir
    );

    Ok(())
}

fn plonk_bn254_artifacts_dir() -> PathBuf {
    home_dir()
        .unwrap()
        .join(".sp1")
        .join("circuits")
        .join("plonk_bn254")
        .join(sphinx_prover::install::PLONK_BN254_ARTIFACTS_COMMIT)
}

fn download_artifacts_from_private_aws() -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dir();
    if build_dir.exists() {
        info!(
            "[contracts-generator] plonk bn254 artifacts already seem to exist at {}. if you want to re-download them, delete the directory",
            build_dir.display()
        );
    } else {
        info!(
            "[contracts-generator] plonk bn254 artifacts for commit {} do not exist at {}. downloading...",
            sphinx_prover::install::PLONK_BN254_ARTIFACTS_COMMIT,
            build_dir.display()
        );

        create_dir_all(build_dir.clone()).unwrap();

        let archive_path = format!("{}.tar.gz", build_dir.to_str().unwrap());
        let mut res = Command::new("aws")
            .args([
                "s3",
                "cp",
                format!(
                    "s3://sphinx-plonk-params/{}.tar.gz",
                    sphinx_prover::install::PLONK_BN254_ARTIFACTS_COMMIT
                )
                .as_str(),
                archive_path.as_str(),
            ])
            .spawn()
            .expect("couldn't run `aws` command. Probably it is not installed");
        res.wait().unwrap();

        // Extract the tarball to the build directory.
        let mut res = Command::new("tar")
            .args([
                "-Pxzf",
                archive_path.as_str(),
                "-C",
                build_dir.to_str().unwrap(),
            ])
            .spawn()
            .expect("failed to extract tarball");
        res.wait().unwrap();

        // Remove archive
        let mut res = Command::new("rm")
            .args(["-rf", archive_path.as_str()])
            .spawn()
            .expect("failed to remove the archive");
        res.wait().unwrap();
    }
    build_dir
}
