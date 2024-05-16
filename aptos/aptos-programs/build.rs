use glob::glob;
use std::fs;
use std::path::PathBuf;
use wp1_helper::build_program;

const PROGRAM_PATTERN: &str = "../programs/*";
const TARGET_DIR: &str = "./artifacts";

fn main() {
    // Re-run if the core library changes
    let core_dir = std::path::Path::new("../core");
    println!("cargo:rerun-if-changed={}", core_dir.display());

    // Create the target directory if it doesn't exist
    if !PathBuf::from(TARGET_DIR).exists() {
        fs::create_dir_all(TARGET_DIR).unwrap();
    }

    // Iterate over each directory that matches the pattern
    for entry in glob(PROGRAM_PATTERN).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                build_program(path.to_str().unwrap());

                let dir_name = path.file_name().unwrap().to_str().unwrap();

                let old_path = path.join("elf/riscv32im-succinct-zkvm-elf");
                let new_path = format!("{}/{}-program", TARGET_DIR, dir_name);

                // If the file exists, move and rename it
                if old_path.exists() {
                    fs::rename(old_path, new_path).unwrap();
                    fs::remove_dir_all(path.join("elf")).unwrap();
                }
            }
            Err(e) => panic!("{:?}", e),
        }
    }
}
