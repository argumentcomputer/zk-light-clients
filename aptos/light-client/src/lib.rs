//! A simple script to generate and verify the proof of a given program.

use wp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

#[allow(dead_code)]
fn dummy() {
    // Generate proof.
    utils::setup_logger();
    let mut stdin = SP1Stdin::new();
    let n = 186u32;
    stdin.write(&n);
    let mut proof =
        SP1Prover::prove(aptos_programs::FIBONACCI_PROGRAM, stdin).expect("proving failed");

    // Read output.
    let a = proof.stdout.read::<u128>();
    let b = proof.stdout.read::<u128>();
    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof.
    SP1Verifier::verify(aptos_programs::FIBONACCI_PROGRAM, &proof).expect("verification failed");
    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
