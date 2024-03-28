use thiserror::Error;

#[derive(Debug, Error)]
pub enum LightClientError {
    #[error("[{program}] Failed to prove: {source}")]
    ProvingError {
        program: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
}
