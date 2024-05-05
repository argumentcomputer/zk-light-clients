use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    // Get the command line arguments
    let args: Vec<String> = env::args().collect();

    // Execute each binary
    for binary_name in args.iter().skip(1) {
        execute_binary(binary_name);
    }
}

fn execute_binary(binary_name: &str) {
    let binary_path = format!("benches/{}/target/release/{}", binary_name, binary_name);
    println!("Executing binary: {}", binary_path);

    // Check if the binary exists
    if !Path::new(&binary_path).exists() {
        println!("Building binary: {}", binary_path);

        // If the binary does not exist, build it
        let output = Command::new("cargo")
            .args(["build", "--release"])
            .env("RUSTFLAGS", "--cfg tokio_unstable -C target-cpu=native")
            .current_dir(format!("benches/{binary_name}")) // Change to the directory of the binary crate
            .output()
            .expect("Failed to execute command");

        // Print the output of the build command
        println!(
            "[{binary_name}] Build stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!(
            "[{binary_name}] Build stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Execute the binary
    let output = Command::new(&binary_path)
        .output()
        .expect("Failed to execute binary");

    // Print the output of the binary
    println!(
        "[{binary_name}] Execution stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!(
        "[{binary_name}] Execution stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
