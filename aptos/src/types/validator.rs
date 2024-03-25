// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::prefixed_sha3;
use crate::crypto::sig::{AggregateSignature, BitVec, PublicKey};
use crate::types::error::VerifyError;
use crate::types::ledger_info::LedgerInfo;
use crate::types::AccountAddress;
use getset::CopyGetters;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use test_strategy::Arbitrary;

#[derive(Default, Debug, Clone, PartialEq, Eq, CopyGetters, Serialize, Deserialize, Arbitrary)]
pub struct ValidatorConsensusInfo {
    #[getset(get_copy)]
    address: AccountAddress,
    #[getset(get_copy)]
    public_key: PublicKey, // bls12-381
    voting_power: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Arbitrary)] // this derive is in the original code, but it's probably a bug, as Validator set comparisons should have set (not list) semantics
pub struct ValidatorVerifier {
    /// A vector of each validator's on-chain account address to its pubkeys and voting power.
    validator_infos: Vec<ValidatorConsensusInfo>,
    // Recomputed on deserialization:
    // // The minimum voting power required to achieve a quorum
    // #[serde(skip)]
    // quorum_voting_power: u128,
    // // Total voting power of all validators (cached from address_to_validator_info)
    // #[serde(skip)]
    // total_voting_power: u128,
    // // In-memory index of account address to its index in the vector, does not go through serde.
    // #[serde(skip)]
    // address_to_validator_index: HashMap<AccountAddress, usize>,
}

impl ValidatorVerifier {
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        Self { validator_infos }
    }

    /// Returns the number of authors to be validated.
    pub fn len(&self) -> usize {
        self.validator_infos.len()
    }

    /// Ensure there are not more than the maximum expected voters (all possible signatures).
    fn check_num_of_voters(
        num_validators: u16,
        bitvec: &BitVec,
    ) -> std::result::Result<(), VerifyError> {
        if bitvec.num_buckets() != BitVec::required_buckets(num_validators) {
            return Err(VerifyError::InvalidBitVec);
        }
        if let Some(last_bit) = bitvec.last_set_bit() {
            if last_bit >= num_validators {
                return Err(VerifyError::InvalidBitVec);
            }
        }
        Ok(())
    }

    /// Returns sum of voting power from Map of validator account addresses, validator consensus info
    fn s_voting_power(address_to_validator_info: &[ValidatorConsensusInfo]) -> u128 {
        address_to_validator_info.iter().fold(0, |sum, x| {
            sum.checked_add(x.voting_power as u128)
                .expect("sum of all voting power is greater than u64::max")
        })
    }

    // TODO: Make this more efficient
    pub fn total_voting_power(&self) -> u128 {
        Self::s_voting_power(&self.validator_infos[..])
    }

    pub fn quorum_voting_power(&self) -> u128 {
        if self.validator_infos.is_empty() {
            0
        } else {
            self.total_voting_power() * 2 / 3 + 1
        }
    }

    /// Returns the voting power for this address.
    pub fn get_voting_power(&self, author: &AccountAddress) -> Option<u64> {
        // TODO : make this more efficient
        let address_to_validator_index = self
            .validator_infos
            .iter()
            .enumerate()
            .map(|(index, info)| (info.address, index))
            .collect::<HashMap<_, _>>();

        address_to_validator_index
            .get(author)
            .map(|index| self.validator_infos[*index].voting_power)
    }

    /// Sum voting power for valid accounts, exiting early for unknown authors
    pub fn sum_voting_power<'a>(
        &self,
        authors: impl Iterator<Item = &'a AccountAddress>,
    ) -> std::result::Result<u128, VerifyError> {
        let mut aggregated_voting_power = 0;
        for account_address in authors {
            match self.get_voting_power(account_address) {
                Some(voting_power) => aggregated_voting_power += voting_power as u128,
                None => return Err(VerifyError::UnknownAuthor),
            }
        }
        Ok(aggregated_voting_power)
    }

    /// Ensure there is at least quorum_voting_power in the provided signatures and there
    /// are only known authors. According to the threshold verification policy,
    /// invalid public keys are not allowed.
    pub fn check_voting_power<'a>(
        &self,
        authors: impl Iterator<Item = &'a AccountAddress>,
        check_super_majority: bool,
    ) -> std::result::Result<u128, VerifyError> {
        let aggregated_voting_power = self.sum_voting_power(authors)?;

        let target = if check_super_majority {
            self.quorum_voting_power()
        } else {
            self.total_voting_power() - self.quorum_voting_power() + 1
        };

        if aggregated_voting_power < target {
            return Err(VerifyError::TooLittleVotingPower {
                voting_power: aggregated_voting_power,
                expected_voting_power: target,
            });
        }
        Ok(aggregated_voting_power)
    }

    pub fn verify_multi_signatures(
        &self,
        message: &LedgerInfo,
        multi_signature: &AggregateSignature,
    ) -> std::result::Result<(), VerifyError> {
        // Verify the number of signature is not greater than expected.
        Self::check_num_of_voters(self.len() as u16, multi_signature.get_signers_bitvec())?;
        let mut pub_keys = vec![];
        let mut authors = vec![];
        for index in multi_signature.get_signers_bitvec().iter_ones() {
            let validator = self
                .validator_infos
                .get(index)
                .ok_or(VerifyError::UnknownAuthor)?;
            authors.push(validator.address());
            pub_keys.push(validator.public_key());
        }
        // Verify the quorum voting power of the authors
        self.check_voting_power(authors.iter(), true)?;
        if self.quorum_voting_power() == 0 {
            // This should happen only in case of tests.
            // TODO(skedia): Clean up the test behaviors to not rely on empty signature
            // verification
            return Ok(());
        }

        // Verify empty multi signature
        let multi_sig = multi_signature
            .sig()
            .as_ref()
            .ok_or(VerifyError::EmptySignature)?;
        let pk_refs = pub_keys.iter().collect::<Vec<&PublicKey>>();
        // Verify the optimistically aggregated signature.
        let aggregated_key =
            PublicKey::aggregate(pk_refs).map_err(|_| VerifyError::FailedToAggregatePubKey)?;

        // see aptos_crypto::unit_tests::cryptohasher
        let mut bytes = prefixed_sha3(b"LedgerInfo").to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;

        multi_sig
            .verify(&bytes, &aggregated_key)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;
        Ok(())
    }
}

/// Reconstruct fields from the raw data upon deserialization.
impl<'de> Deserialize<'de> for ValidatorVerifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "ValidatorVerifier")]
        struct RawValidatorVerifier {
            validator_infos: Vec<ValidatorConsensusInfo>,
        }

        let RawValidatorVerifier { validator_infos } =
            RawValidatorVerifier::deserialize(deserializer)?;

        Ok(ValidatorVerifier::new(validator_infos))
    }
}
