// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

// SPDX-License-Identifier: Apache-2.0, MIT
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue};
use crate::crypto::sig::{AggregateSignature, BitVec, PublicKey, PUB_KEY_LEN};
use crate::serde_error;
use crate::types::error::{TypesError, VerifyError};
use crate::types::ledger_info::LedgerInfo;
use crate::types::utils::{read_leb128, write_leb128, LEB128_PUBKEY_LEN, VOTING_POWER_OFFSET_INCR};
use crate::types::{AccountAddress, ACCOUNT_ADDRESS_SIZE};
use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};
use getset::Getters;
use serde::{Deserialize, Deserializer, Serialize};

/// Size in bytes for a `ValidatorConsensusInfo`
pub const VALIDATOR_CONSENSUS_INFO_SIZE: usize =
    ACCOUNT_ADDRESS_SIZE + LEB128_PUBKEY_LEN + PUB_KEY_LEN + VOTING_POWER_OFFSET_INCR;

/// `ValidatorConsensusInfo` contains all the necessary
/// information about a validator to assess its participation
/// in the consensus.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorConsensusInfo {
    address: AccountAddress,
    public_key: PublicKey, // bls12-381
    voting_power: u64,
}

impl ValidatorConsensusInfo {
    /// Creates a new `ValidatorConsensusInfo`.
    ///
    /// # Arguments
    ///
    /// * `address: AccountAddress` - The address of the validator.
    /// * `public_key: PublicKey` - The public key of the validator.
    /// * `voting_power: u64` - The voting power of the validator.
    ///
    /// # Returns
    ///
    /// A new `ValidatorConsensusInfo`.
    pub const fn new(address: AccountAddress, public_key: PublicKey, voting_power: u64) -> Self {
        Self {
            address,
            public_key,
            voting_power,
        }
    }

    /// Converts the `ValidatorConsensusInfo` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `ValidatorConsensusInfo`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&self.address.to_bytes());
        bytes.put_slice(&self.public_key.to_bytes());
        bytes.put_u64_le(self.voting_power);
        bytes.to_vec()
    }

    /// Creates a `ValidatorConsensusInfo` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `ValidatorConsensusInfo`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `ValidatorConsensusInfo`
    /// could be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let address = AccountAddress::from_bytes(
            bytes.chunk().get(..ACCOUNT_ADDRESS_SIZE).ok_or_else(|| {
                serde_error!(
                    "ValidatorConsensusInfo",
                    "Not enough data for AccountAddress"
                )
            })?,
        )
        .map_err(|e| serde_error!("ValidatorConsensusInfo", e))?;
        bytes.advance(ACCOUNT_ADDRESS_SIZE); // Advance the buffer by the size of AccountAddress

        let (slice_len, bytes_read) = read_leb128(bytes).map_err(|e| {
            serde_error!(
                "ValidatorConsensusInfo",
                format!("Failed to read length of public_key: {e}")
            )
        })?;
        bytes.advance(bytes_read);

        let public_key =
            PublicKey::from_bytes(bytes.chunk().get(..slice_len as usize).ok_or_else(|| {
                serde_error!("ValidatorConsensusInfo", "Not enough data for PublicKey")
            })?)
            .map_err(|e| serde_error!("ValidatorConsensusInfo", e))?;
        bytes.advance(slice_len as usize); // Advance the buffer by the size of PublicKey
        let voting_power = bytes.get_u64_le();

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "LedgerInfo",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self {
            address,
            public_key,
            voting_power,
        })
    }
}

/// `ValidatorVerifier` represents a list of validators, most
/// of the time related to a given epoch.
#[derive(Default, Debug, Clone, PartialEq, Eq, Getters, Serialize)]
// this derive is in the original code, but it's probably a bug, as Validator set comparisons should have set (not list) semantics
#[getset(get = "pub")]
pub struct ValidatorVerifier {
    /// A vector of each validator's on-chain account address to its pubkeys and voting power.
    validator_infos: Vec<ValidatorConsensusInfo>,
}

impl ValidatorVerifier {
    /// Creates a new `ValidatorVerifier`.
    ///
    /// # Arguments
    ///
    /// * `validator_infos: Vec<ValidatorConsensusInfo>` - A vector of `ValidatorConsensusInfo`.
    ///
    /// # Returns
    ///
    /// A new `ValidatorVerifier`.
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        Self { validator_infos }
    }

    /// Returns the number of authors to be validated.
    ///
    /// # Returns
    ///
    /// The number of authors to be validated.
    pub fn len(&self) -> usize {
        self.validator_infos.len()
    }

    /// Checks if the `ValidatorVerifier` is empty.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the `ValidatorVerifier` is empty.
    pub fn is_empty(&self) -> bool {
        self.validator_infos.is_empty()
    }

    /// Ensure there are not more than the maximum expected voters (all possible signatures).
    ///
    /// # Arguments
    ///
    /// * `num_validators: u16` - The number of validators.
    /// * `bitvec: &BitVec` - The bit vector of validators.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the number of voters is valid, and `Err` otherwise.
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

    /// Returns sum of voting power from Map of validator
    /// account addresses, validator consensus info.
    ///
    /// # Returns
    ///
    /// The total voting power of the `ValidatorVerifier`.
    fn s_voting_power(address_to_validator_info: &[ValidatorConsensusInfo]) -> u128 {
        address_to_validator_info.iter().fold(0, |sum, x| {
            sum.checked_add(u128::from(x.voting_power))
                .expect("sum of all voting power is greater than u64::max")
        })
    }

    /// Returns the total voting power of the `ValidatorVerifier`.
    ///
    /// # Returns
    ///
    /// The total voting power of the `ValidatorVerifier`.
    // TODO: Make this more efficient
    pub fn total_voting_power(&self) -> u128 {
        Self::s_voting_power(&self.validator_infos[..])
    }

    /// Returns the quorum voting power of the `ValidatorVerifier`,
    /// which is 2 / 3 + 1 of the total voting power.
    ///
    /// # Returns
    ///
    /// The quorum voting power of the `ValidatorVerifier`.
    pub fn quorum_voting_power(&self) -> u128 {
        if self.validator_infos.is_empty() {
            0
        } else {
            self.total_voting_power() * 2 / 3 + 1
        }
    }

    /// Returns the voting power for this address.
    ///
    /// # Arguments
    ///
    /// * `author: &AccountAddress` - The address of the author.
    ///
    /// # Returns
    ///
    /// The voting power for this address.
    pub fn get_voting_power(&self, author: &AccountAddress) -> Option<u64> {
        self.validator_infos.iter().find_map(|info| {
            if &info.address == author {
                Some(info.voting_power)
            } else {
                None
            }
        })
    }

    /// Sum voting power for valid accounts, exiting early for unknown authors
    ///
    /// # Arguments
    ///
    /// * `authors: impl Iterator<Item = &AccountAddress>` - An iterator of account addresses.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the sum of voting power is valid, and `Err` otherwise.
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
    ///
    /// # Arguments
    ///
    /// * `authors: impl Iterator<Item = &AccountAddress>` - An iterator of account addresses.
    /// * `check_super_majority: bool` - A boolean indicating whether to check super majority.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the voting power is valid, and `Err` otherwise.
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

    /// Verifies the multi-signatures of a given `LedgerInfo`
    /// with the provided `AggregateSignature` from the
    /// `ValidatorVerifier`.
    ///
    /// # Arguments
    ///
    /// * `message: &LedgerInfo` - The ledger info.
    /// * `multi_signature: &AggregateSignature` - The aggregate signature.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the multi-signatures are valid, and `Err` otherwise.
    pub fn verify_multi_signatures(
        &self,
        message: &LedgerInfo,
        multi_signature: &AggregateSignature,
    ) -> std::result::Result<(), VerifyError> {
        // Verify the number of signature is not greater than expected.
        Self::check_num_of_voters(self.len() as u16, multi_signature.validator_bitmask())?;
        let mut pub_keys = vec![];
        let mut authors = vec![];
        for index in multi_signature.validator_bitmask().iter_ones() {
            let validator = self
                .validator_infos
                .get(index)
                .ok_or(VerifyError::UnknownAuthor)?;
            authors.push(&validator.address);
            pub_keys.push(&validator.public_key);
        }

        // Verify the quorum voting power of the authors
        self.check_voting_power(authors.into_iter(), true)?;
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

        // Verify the optimistically aggregated signature.
        let aggregated_key =
            PublicKey::aggregate(&pub_keys).map_err(|_| VerifyError::FailedToAggregatePubKey)?;

        // see aptos_crypto::unit_tests::cryptohasher
        let mut bytes = prefixed_sha3(b"LedgerInfo").to_vec();
        bytes.extend_from_slice(&message.to_bytes());

        multi_sig
            .verify(&bytes, &aggregated_key)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;
        Ok(())
    }

    /// Converts the `ValidatorVerifier` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `ValidatorVerifier`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_slice(&write_leb128(self.validator_infos.len() as u64));
        for info in &self.validator_infos {
            bytes.put_slice(&info.to_bytes());
        }
        bytes.to_vec()
    }

    /// Creates a `ValidatorVerifier` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `ValidatorVerifier`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `ValidatorVerifier`
    /// could be successfully created, and `Err` otherwise.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let mut validator_infos = Vec::new();

        let (slice_len, bytes_read) = read_leb128(bytes).map_err(|_| {
            serde_error!(
                "ValidatorVerifier",
                "Failed to read length of validator_infos"
            )
        })?;

        bytes.advance(bytes_read);

        for _ in 0..slice_len {
            let info_bytes = bytes
                .chunk()
                .get(..VALIDATOR_CONSENSUS_INFO_SIZE)
                .ok_or_else(|| {
                    serde_error!(
                        "ValidatorVerifier",
                        "Not enough data for ValidatorConsensusInfo"
                    )
                })?;
            validator_infos.push(
                ValidatorConsensusInfo::from_bytes(info_bytes)
                    .map_err(|e| serde_error!("ValidatorVerifier", e))?,
            );
            bytes.advance(VALIDATOR_CONSENSUS_INFO_SIZE);
        }

        if bytes.remaining() != 0 {
            return Err(serde_error!(
                "ValidatorVerifier",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self { validator_infos })
    }

    /// Estimate the size in bytes for  `ValidatorVerifier` from the given bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to estimate the size.
    ///
    /// # Returns
    ///
    /// The estimated size in bytes for the structure.
    ///
    /// # Note
    ///
    /// The `ValidatorVerifier` bytes should start from offset 0 of the slice.
    pub(crate) fn estimate_size_from_bytes(bytes: &[u8]) -> Result<usize, TypesError> {
        let (slice_len, bytes_read) =
            read_leb128(bytes).map_err(|e| serde_error!("ValidatorVerifier", e))?;
        Ok(slice_len as usize * VALIDATOR_CONSENSUS_INFO_SIZE + bytes_read)
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

#[cfg(all(test, feature = "aptos"))]
mod test {
    use proptest::prelude::ProptestConfig;
    use proptest::proptest;

    #[test]
    fn test_bytes_conversion_validator_consensus_info() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::types::ledger_info::LedgerInfoWithSignatures;
        use crate::types::validator::ValidatorConsensusInfo;

        let mut aptos_wrapper = AptosWrapper::new(2, 130, 130).unwrap();

        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn test_bytes_conversion_validator_verifier(
            validators in 130..136,
            signers in 95..101
        ) {
            use crate::aptos_test_utils::wrapper::AptosWrapper;
            use crate::types::validator::ValidatorVerifier;

            let mut aptos_wrapper = AptosWrapper::new(2, validators as usize, signers  as usize).unwrap();

            aptos_wrapper.generate_traffic().unwrap();
            aptos_wrapper.commit_new_epoch().unwrap();

            let bytes = bcs::to_bytes(
                &aptos_wrapper
                .get_latest_li().expect("Could not retrieve latest LedgetInfoWithSignatures")
                .ledger_info()
                .next_epoch_state().expect("LedgerInfoWithSignatures should contain a new EpochState")
                .verifier
            ).expect("Failed to serialize ValidatorVerifier");
            let validator_from_bytes = ValidatorVerifier::from_bytes(&bytes).unwrap();
            let validator_to_bytes = validator_from_bytes.to_bytes();

            assert_eq!(bytes, validator_to_bytes);
        }
    }
}
