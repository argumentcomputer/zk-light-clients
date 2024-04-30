pub const MERKLE_PROGRAM: &[u8] = include_bytes!("../artifacts/merkle-program");

pub const RATCHET_PROGRAM: &[u8] = include_bytes!("../artifacts/ratchet-program");

pub mod bench {
    pub const BYTES: &[u8] = include_bytes!("../artifacts/bytes-program");
    pub const SIGNATURE_VERIFICATION_PROGRAM: &[u8] =
        include_bytes!("../artifacts/signature-verification-program");
}
