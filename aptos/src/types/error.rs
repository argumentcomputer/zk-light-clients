// SPDX-License-Identifier: Apache-2.0, MIT
use thiserror::Error;

/// Errors possible during signature verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("Author is unknown")]
    /// The author for this signature is unknown by this validator.
    UnknownAuthor,
    #[error(
        "The voting power ({}) is less than expected voting power ({})",
        voting_power,
        expected_voting_power
    )]
    TooLittleVotingPower {
        voting_power: u128,
        expected_voting_power: u128,
    },
    #[error("Signature is empty")]
    /// The signature is empty
    EmptySignature,
    #[error("Multi signature is invalid")]
    /// The multi signature is invalid
    InvalidMultiSignature,
    #[error("Aggregated signature is invalid")]
    /// The multi signature is invalid
    InvalidAggregatedSignature,
    #[error("Inconsistent Block Info")]
    InconsistentBlockInfo,
    #[error("Failed to aggregate public keys")]
    FailedToAggregatePubKey,
    #[error("Failed to aggregate signatures")]
    FailedToAggregateSignature,
    #[error("Failed to verify multi-signature")]
    FailedToVerifyMultiSignature,
    #[error("Invalid bitvec from the multi-signature")]
    InvalidBitVec,
    #[error("Failed to verify aggreagated signature")]
    FailedToVerifyAggregatedSignature,
}
