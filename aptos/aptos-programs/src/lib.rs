pub const INCLUSION_PROGRAM: &[u8] = include_bytes!("../artifacts/inclusion-program");

pub const EPOCH_CHANGE_PROGRAM: &[u8] = include_bytes!("../artifacts/epoch-change-program");

pub mod bench {
    pub const SIGNATURE_VERIFICATION_PROGRAM: &[u8] =
        include_bytes!("../artifacts/benchmarks/signature-verification-program");
}
