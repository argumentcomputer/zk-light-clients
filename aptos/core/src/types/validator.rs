// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
use crate::crypto::sig::{AggregateSignature, BitVec, PublicKey, PUB_KEY_LEN};
use crate::types::error::{TypesError, VerifyError};
use crate::types::ledger_info::{LedgerInfo, LEB128_PUBKEY_LEN, VOTING_POWER_OFFSET_INCR};
use crate::types::utils::{read_leb128, write_leb128};
use crate::types::{AccountAddress, ACCOUNT_ADDRESS_SIZE};
use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

#[derive(Default, Debug, Clone, PartialEq, Eq, CopyGetters, Serialize, Deserialize)]
pub struct ValidatorConsensusInfo {
    #[getset(get_copy)]
    address: AccountAddress,
    #[getset(get_copy)]
    public_key: PublicKey,
    // bls12-381
    voting_power: u64,
}

impl ValidatorConsensusInfo {
    pub const fn new(address: AccountAddress, public_key: PublicKey, voting_power: u64) -> Self {
        Self {
            address,
            public_key,
            voting_power,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.address.to_bytes());
        bytes.put_slice(&self.public_key.to_bytes());
        bytes.put_u64_le(self.voting_power);
        bytes.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let address =
            AccountAddress::from_bytes(bytes.chunk().get(..ACCOUNT_ADDRESS_SIZE).ok_or_else(
                || TypesError::DeserializationError {
                    structure: String::from("ValidatorConsensusInfo"),
                    source: "Not enough data for AccountAddress".into(),
                },
            )?)
            .map_err(|e| TypesError::DeserializationError {
                structure: String::from("ValidatorConsensusInfo"),
                source: e.into(),
            })?;
        bytes.advance(ACCOUNT_ADDRESS_SIZE); // Advance the buffer by the size of AccountAddress

        let (slice_len, bytes_read) =
            read_leb128(bytes).map_err(|e| TypesError::DeserializationError {
                structure: String::from("ValidatorConsensusInfo"),
                source: format!("Failed to read length of public_key: {e}").into(),
            })?;
        bytes.advance(bytes_read);

        let public_key =
            PublicKey::from_bytes(bytes.chunk().get(..slice_len as usize).ok_or_else(|| {
                TypesError::DeserializationError {
                    structure: String::from("ValidatorConsensusInfo"),
                    source: "Not enough data for PublicKey".into(),
                }
            })?)
            .map_err(|e| TypesError::DeserializationError {
                structure: String::from("ValidatorConsensusInfo"),
                source: e.into(),
            })?;
        bytes.advance(slice_len as usize); // Advance the buffer by the size of PublicKey
        let voting_power = bytes.get_u64_le();
        Ok(Self {
            address,
            public_key,
            voting_power,
        })
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Getters, Serialize)]
// this derive is in the original code, but it's probably a bug, as Validator set comparisons should have set (not list) semantics
#[getset(get = "pub")]
pub struct ValidatorVerifier {
    /// A vector of each validator's on-chain account address to its pubkeys and voting power.
    validator_infos: Vec<ValidatorConsensusInfo>,
}

impl ValidatorVerifier {
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        Self { validator_infos }
    }

    /// Returns the number of authors to be validated.
    pub fn len(&self) -> usize {
        self.validator_infos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validator_infos.is_empty()
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
            sum.checked_add(u128::from(x.voting_power))
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
                Some(voting_power) => aggregated_voting_power += u128::from(voting_power),
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
        let pk_refs = pub_keys.iter_mut().collect::<Vec<_>>();
        // Verify the optimistically aggregated signature.
        let mut aggregated_key =
            PublicKey::aggregate(pk_refs).map_err(|_| VerifyError::FailedToAggregatePubKey)?;

        // see aptos_crypto::unit_tests::cryptohasher
        let mut bytes = prefixed_sha3(b"LedgerInfo").to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;

        multi_sig
            .verify(&bytes, &mut aggregated_key)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&write_leb128(self.validator_infos.len() as u64));
        for info in &self.validator_infos {
            bytes.put_slice(&info.to_bytes());
        }
        bytes.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let mut validator_infos = Vec::new();
        println!("cycle-tracker-start: read_leb_advance");
        let (slice_len, bytes_read) =
            read_leb128(bytes).map_err(|_| TypesError::DeserializationError {
                structure: String::from("ValidatorVerifier"),
                source: "Failed to read length of validator_infos".into(),
            })?;

        bytes.advance(bytes_read);
        println!("cycle-tracker-end: read_leb_advance");

        // 32 bytes (address) + size byte + 48 bytes (public key) + 8 bytes (voting power)
        println!("cycle-tracker-start: all_validator_infos_{}", slice_len);
        const INFO_LEN: usize =
            ACCOUNT_ADDRESS_SIZE + LEB128_PUBKEY_LEN + PUB_KEY_LEN + VOTING_POWER_OFFSET_INCR;
        for _ in 0..slice_len {
            let info_bytes =
                bytes
                    .chunk()
                    .get(..INFO_LEN)
                    .ok_or_else(|| TypesError::DeserializationError {
                        structure: String::from("ValidatorVerifier"),
                        source: "Not enough data for ValidatorConsensusInfo".into(),
                    })?;
            validator_infos.push(ValidatorConsensusInfo::from_bytes(info_bytes).map_err(|e| {
                TypesError::DeserializationError {
                    structure: String::from("ValidatorVerifier"),
                    source: e.into(),
                }
            })?);
            bytes.advance(INFO_LEN);
        }
        println!("cycle-tracker-end: all_validator_infos_{}", slice_len);

        Ok(Self { validator_infos })
    }
}

impl CryptoHash for ValidatorVerifier {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"ValidatorVerifier"),
            vec![&self.to_bytes()],
        ))
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

#[cfg(test)]
mod test {

    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_validator_consensus_info() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::types::ledger_info::LedgerInfoWithSignatures;
        use crate::types::validator::ValidatorConsensusInfo;
        use crate::NBR_VALIDATORS;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        // We can use our intern struct as we test that the conversion is correct with bcs in
        // aptos_test_utils
        let intern_li: LedgerInfoWithSignatures =
            bcs::from_bytes(&aptos_wrapper.get_latest_li_bytes().unwrap()).unwrap();
        let validator_consensus_info = intern_li
            .ledger_info()
            .next_epoch_state()
            .unwrap()
            .verifier
            .validator_infos()[0]
            .clone();

        let bytes = bcs::to_bytes(&validator_consensus_info).unwrap();

        let validator_from_bytes = ValidatorConsensusInfo::from_bytes(&bytes).unwrap();
        let validator_to_bytes = validator_from_bytes.to_bytes();

        assert_eq!(bytes, validator_to_bytes);
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_validator_verifier() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::types::ledger_info::{OFFSET_VALIDATOR_LIST, VALIDATORS_LIST_LEN};
        use crate::types::validator::ValidatorVerifier;
        use crate::NBR_VALIDATORS;

        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS);

        aptos_wrapper.generate_traffic();
        aptos_wrapper.commit_new_epoch();

        let bytes = &aptos_wrapper
            .get_latest_li_bytes()
            .unwrap()
            .iter()
            .skip(OFFSET_VALIDATOR_LIST)
            .take(VALIDATORS_LIST_LEN)
            .copied()
            .collect::<Vec<u8>>();
        let validator_from_bytes = ValidatorVerifier::from_bytes(bytes).unwrap();
        let validator_to_bytes = validator_from_bytes.to_bytes();

        assert_eq!(bytes, &validator_to_bytes);
    }
}
