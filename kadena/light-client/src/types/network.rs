use crate::proofs::longest_chain::LongestChainIn;
use crate::proofs::{ProofType, ProvingMode};
use anyhow::{anyhow, Error};

#[derive(Debug)]
pub enum Request {
    /// Request to prove the longest chain for Kadena.
    ProveLongestChain(Box<(ProvingMode, LongestChainIn)>),
    /// Request to verify the validity of a proof for the longest chain
    VerifyLongestChain(Box<ProofType>),
}

impl Request {
    /// Returns a serialized representation of the enum.
    ///
    /// # Returns
    ///
    /// A Vec<u8> representing the enum.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            Request::ProveLongestChain(boxed) => {
                let mut bytes = vec![0];

                let (proving_mode, longest_chain_in) = boxed.as_ref();

                bytes.push(proving_mode.to_bytes());
                bytes.extend_from_slice(&longest_chain_in.to_bytes());
                Ok(bytes)
            }
            Request::VerifyLongestChain(proof_type) => {
                let mut bytes = vec![1];
                bytes.extend_from_slice(&proof_type.to_bytes().map_err(|e| anyhow!(e))?);
                Ok(bytes)
            }
        }
    }

    /// Returns a Request from a serialized representation.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized representation of the enum.
    ///
    /// # Returns
    ///
    /// The Request.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes[0] {
            0 => {
                let proving_mode = ProvingMode::from_bytes(&bytes[1..2])?;

                let longest_chain_in = LongestChainIn::from_bytes(&bytes[2..])?;

                Ok(Request::ProveLongestChain(Box::new((
                    proving_mode,
                    longest_chain_in,
                ))))
            }
            1 => {
                let proof_type = ProofType::from_bytes(&bytes[1..])?;
                Ok(Request::VerifyLongestChain(Box::new(proof_type)))
            }
            _ => Err(anyhow!("Invalid request")),
        }
    }
}
