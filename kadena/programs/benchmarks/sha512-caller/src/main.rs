#![no_main]
sphinx_zkvm::entrypoint!(main);

use sha2::{Digest, Sha512_256};

pub fn main() {
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: read_inputs");
    }
    let preimage = sphinx_zkvm::io::read::<Vec<u8>>();
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: read_inputs");
    }

    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-start: hashing");
    }
    let hash = Sha512_256::digest(preimage);
    let mut ret = [0u8; 32];
    ret.copy_from_slice(&hash);
    sphinx_zkvm::precompiles::unconstrained! {
                println!("cycle-tracker-end: hashing");
    }

    sphinx_zkvm::io::commit::<[u8; 32]>(&ret);
}
