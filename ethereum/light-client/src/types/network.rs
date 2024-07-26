use crate::proofs::committee_change::CommitteeChangeIn;
use crate::proofs::inclusion::StorageInclusionIn;
use crate::proofs::{ProofType, ProvingMode};
use anyhow::{anyhow, Error};

#[derive(Debug)]
pub enum Request {
    /// Request to prove the validity of a sync committee change.
    ProveCommitteeChange(Box<(ProvingMode, CommitteeChangeIn)>),
    /// Request to verify the validity of a proof for a sync committee change.
    VerifyCommitteeChange(ProofType),
    /// Request to prove the inclusion of value in the chain storage.
    ProveInclusion(Box<(ProvingMode, StorageInclusionIn)>),
    /// Request to verify the validity of a proof for the inclusion of value in the chain storage.
    VerifyInclusion(ProofType),
}

impl Request {
    /// Returns a serialized representation of the enum.
    ///
    /// # Returns
    ///
    /// A Vec<u8> representing the enum.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            Request::ProveCommitteeChange(boxed) => {
                let mut bytes = vec![0];

                let (proving_mode, committee_change_in) = boxed.as_ref();

                bytes.push(proving_mode.to_bytes());
                bytes.extend_from_slice(
                    &committee_change_in.to_ssz_bytes().map_err(|e| anyhow!(e))?,
                );
                Ok(bytes)
            }
            Request::VerifyCommitteeChange(proof_type) => {
                let mut bytes = vec![1];
                bytes.extend_from_slice(&proof_type.to_bytes().map_err(|e| anyhow!(e))?);
                Ok(bytes)
            }
            Request::ProveInclusion(boxed) => {
                let mut bytes = vec![2];

                let (proving_mode, storage_inclusion_in) = boxed.as_ref();

                bytes.push(proving_mode.to_bytes());
                bytes.extend_from_slice(
                    &storage_inclusion_in
                        .to_ssz_bytes()
                        .map_err(|e| anyhow!(e))?,
                );
                Ok(bytes)
            }
            Request::VerifyInclusion(proof_type) => {
                let mut bytes = vec![3];
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

                let committee_change_in = CommitteeChangeIn::from_ssz_bytes(&bytes[2..])?;

                Ok(Request::ProveCommitteeChange(Box::new((
                    proving_mode,
                    committee_change_in,
                ))))
            }
            1 => {
                let proof_type = ProofType::from_bytes(&bytes[1..])?;
                Ok(Request::VerifyCommitteeChange(proof_type))
            }
            2 => {
                let proving_mode = ProvingMode::from_bytes(&bytes[1..2])?;

                let storage_inclusion_in = StorageInclusionIn::from_ssz_bytes(&bytes[2..])?;

                Ok(Request::ProveInclusion(Box::new((
                    proving_mode,
                    storage_inclusion_in,
                ))))
            }
            3 => {
                let proof_type = ProofType::from_bytes(&bytes[1..])?;
                Ok(Request::VerifyInclusion(proof_type))
            }
            _ => Err(anyhow!("Invalid request")),
        }
    }
}
