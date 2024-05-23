pub const INCLUSION_PROGRAM: &[u8] = include_bytes!("../artifacts/inclusion-program");

pub const EPOCH_CHANGE_PROGRAM: &[u8] = include_bytes!("../artifacts/epoch-change-program");

pub mod bench {
    pub const BYTES: &[u8] = include_bytes!("../artifacts/benchmarks/bytes-program");
    pub const SIGNATURE_VERIFICATION_PROGRAM: &[u8] =
        include_bytes!("../artifacts/benchmarks/signature-verification-program");
}
