// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Transaction Module
//!
//! This module provides the `TransactionInfo` structure
//! and associated methods for handling transaction information
//! in the Aptos Light Client.
//!
//! The `TransactionInfo` structure represents the information
//! about how a transaction affects the state of the Aptos blockchain.

// SPDX-License-Identifier: Apache-2.0
use crate::crypto::hash::{hash_data, prefixed_sha3, CryptoHash, HashValue, HASH_LENGTH};
use crate::serde_error;
use crate::types::error::TypesError;
use crate::types::utils::{ENUM_VARIANT_LEN, U64_SIZE};
use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};

/// `TransactionInfo` contains Information related to how
/// a transaction affected the state of the Aptos blockchain.
///
/// It is implemented as an enum to allow for future expansion
/// of the transaction info.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionInfo {
    V0(TransactionInfoV0),
}

impl TransactionInfo {
    /// Returns the state checkpoint of the `TransactionInfo`.
    ///
    /// # Returns
    ///
    /// The state checkpoint of the `TransactionInfo`.
    pub const fn state_checkpoint(&self) -> Option<HashValue> {
        match self {
            TransactionInfo::V0(info) => info.state_checkpoint_hash,
        }
    }

    /// Converts the `TransactionInfo` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `TransactionInfo`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        match self {
            TransactionInfo::V0(info) => {
                bytes.put_u8(0);
                bytes.put_slice(&info.to_bytes());
            }
        }
        bytes.to_vec()
    }

    /// Creates a `TransactionInfo` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `TransactionInfo`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `TransactionInfo`
    /// could be successfully created, and `Err` otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let mut buf = BytesMut::from(bytes);
        let tx_info = match buf.get_u8() {
            0 => {
                let tx_info_v0 = TransactionInfoV0::from_bytes(
                    buf.chunk().get(..TRANSACTION_INFO_V0_SIZE).ok_or_else(|| {
                        serde_error!("TransactionInfo", "Not enough data for TransactionInfoV0")
                    })?,
                )?;
                buf.advance(TRANSACTION_INFO_V0_SIZE);
                TransactionInfo::V0(tx_info_v0)
            }
            _ => return Err(serde_error!("TransactionInfo", "Invalid variant")),
        };

        if buf.remaining() != 0 {
            return Err(serde_error!(
                "TransactionInfo",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(tx_info)
    }
}

impl CryptoHash for TransactionInfo {
    fn hash(&self) -> HashValue {
        HashValue::new(hash_data(
            &prefixed_sha3(b"TransactionInfo"),
            vec![&self.to_bytes()],
        ))
    }
}

/// Length in bytes of the serialized `TransactionInfoV0`.
pub const TRANSACTION_INFO_V0_SIZE: usize =
    U64_SIZE + 4 * HASH_LENGTH + 2 * ENUM_VARIANT_LEN + EXECUTION_STATUS_SIZE;

/// `TransactionInfoV0`  contains Information related to how
/// a transaction affected the state of the Aptos blockchain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionInfoV0 {
    /// The amount of gas used.
    gas_used: u64,

    /// The vm status. If it is not `Executed`, this will provide the general error class. Execution
    /// failures and Move abort's receive more detailed information. But other errors are generally
    /// categorized with no status code or other information
    status: ExecutionStatus,

    /// The hash of this transaction.
    transaction_hash: HashValue,

    /// The root hash of Merkle Accumulator storing all events emitted during this transaction.
    event_root_hash: HashValue,

    /// The hash value summarizing all changes caused to the world state by this transaction.
    /// i.e. hash of the output write set.
    state_change_hash: HashValue,

    /// The root hash of the Sparse Merkle Tree describing the world state at the end of this
    /// transaction. Depending on the protocol configuration, this can be generated periodical
    /// only, like per block.
    state_checkpoint_hash: Option<HashValue>,

    /// Potentially summarizes all evicted items from state. Always `None` for now.
    state_cemetery_hash: Option<HashValue>,
}

impl TransactionInfoV0 {
    /// Converts the `TransactionInfoV0` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `TransactionInfoV0
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        bytes.put_u64_le(self.gas_used);
        bytes.put_slice(&self.status.to_bytes());
        bytes.put_slice(self.transaction_hash.as_ref());
        bytes.put_slice(self.event_root_hash.as_ref());
        bytes.put_slice(self.state_change_hash.as_ref());
        match &self.state_checkpoint_hash {
            Some(hash) => {
                bytes.put_u8(1);
                bytes.put_slice(hash.as_ref());
            }
            None => bytes.put_u8(0),
        }
        match &self.state_cemetery_hash {
            Some(hash) => {
                bytes.put_u8(1);
                bytes.put_slice(hash.as_ref());
            }
            None => bytes.put_u8(0),
        }
        bytes.to_vec()
    }

    /// Creates a `TransactionInfoV0` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `TransactionInfoV0`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `TransactionInfoV0`
    /// could be successfully created, and `Err` otherwise.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let mut buf = BytesMut::from(bytes);

        let gas_used = buf.get_u64_le();

        let status =
            ExecutionStatus::from_bytes(buf.chunk().get(..EXECUTION_STATUS_SIZE).ok_or_else(
                || serde_error!("TransactionInfo0", "Not enough data for ExecutionStatus"),
            )?)?;
        buf.advance(EXECUTION_STATUS_SIZE);

        let transaction_hash =
            HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                serde_error!("TransactionInfo0", "Not enough data for transaction hash")
            })?)
            .unwrap();
        buf.advance(HASH_LENGTH);

        let event_root_hash =
            HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                serde_error!("TransactionInfo0", "Not enough data for event root hash")
            })?)
            .unwrap();
        buf.advance(HASH_LENGTH);

        let state_change_hash =
            HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                serde_error!("TransactionInfo0", "Not enough data for statechange hash")
            })?)
            .unwrap();
        buf.advance(HASH_LENGTH);

        let state_checkpoint_hash = if buf.get_u8() == 1 {
            Some(
                HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                    serde_error!(
                        "TransactionInfo0",
                        "Not enough data for state checkpoint hash"
                    )
                })?)
                .unwrap(),
            )
        } else {
            None
        };
        buf.advance(HASH_LENGTH);

        let state_cemetery_hash = if buf.get_u8() == 1 {
            let hash_value =
                HashValue::from_slice(buf.chunk().get(..HASH_LENGTH).ok_or_else(|| {
                    serde_error!(
                        "TransactionInfo0",
                        "Not enough data for state cemetery hash"
                    )
                })?)
                .unwrap();
            buf.advance(HASH_LENGTH);
            Some(hash_value)
        } else {
            None
        };

        if buf.remaining() != 0 {
            return Err(serde_error!(
                "TransactionInfoV0",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(Self {
            gas_used,
            status,
            transaction_hash,
            event_root_hash,
            state_change_hash,
            state_checkpoint_hash,
            state_cemetery_hash,
        })
    }
}

/// Length in bytes of the serialized `ExecutionStatus`. We only
/// expect to receive successful transactions included  in the block to
/// prove account inclusion.
pub const EXECUTION_STATUS_SIZE: usize = ENUM_VARIANT_LEN;

/// The status of VM execution, which contains more detailed failure info.
/// We only expect to handle successful transactions in the light client,
/// as we use it for state checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Success,
}

impl ExecutionStatus {
    /// Converts the `ExecutionStatus` to a byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` representing the `ExecutionStatus
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        match self {
            ExecutionStatus::Success => {
                bytes.put_u8(0);
            }
        }
        bytes.to_vec()
    }
    /// Creates a `ExecutionStatus` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes: &[u8]` - A byte slice from which to create the `ExecutionStatus`.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the `ExecutionStatus`
    /// could be successfully created, and `Err` otherwise.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let mut buf = BytesMut::from(bytes);
        let execution_status = match buf.get_u8() {
            0 => ExecutionStatus::Success,
            _ => {
                return Err(serde_error!(
                    "ExecutionStatus",
                    "Invalid variant, expected only success"
                ))
            }
        };

        if buf.remaining() != 0 {
            return Err(serde_error!(
                "ExecutionStatus",
                "Unexpected data after completing deserialization"
            ));
        }

        Ok(execution_status)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_bytes_conversion_execution_status() {
        use crate::types::transaction::ExecutionStatus;

        // Test ExecutionStatus::Success
        let execution_status = ExecutionStatus::Success;
        let execution_status_ser_bcs = bcs::to_bytes(&execution_status).unwrap();
        let execution_status_from_bcs =
            ExecutionStatus::from_bytes(&execution_status_ser_bcs).unwrap();

        assert_eq!(execution_status, execution_status_from_bcs);

        let execution_status_to_bytes = execution_status_from_bcs.to_bytes();

        assert_eq!(execution_status_ser_bcs, execution_status_to_bytes);
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_bytes_conversion_transaction_info() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::types::transaction::TransactionInfo;

        let mut aptos_wrapper = AptosWrapper::new(40, 1, 1).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let proof_assets = aptos_wrapper.get_latest_proof_account(35).unwrap();

        let aptos_transaction = proof_assets.transaction();
        let aptos_transaction_bytes = bcs::to_bytes(aptos_transaction).unwrap();

        let lc_transaction = TransactionInfo::from_bytes(&aptos_transaction_bytes).unwrap();

        let lc_transaction_bytes = lc_transaction.to_bytes();

        assert_eq!(aptos_transaction_bytes, lc_transaction_bytes);
    }

    #[cfg(feature = "aptos")]
    #[test]
    fn test_hash_transaction_info() {
        use crate::aptos_test_utils::wrapper::AptosWrapper;
        use crate::crypto::hash::CryptoHash as LcCryptoHash;
        use crate::types::transaction::TransactionInfo;
        use aptos_crypto::hash::CryptoHash as AptosCryptoHash;

        let mut aptos_wrapper = AptosWrapper::new(40, 1, 1).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let proof_assets = aptos_wrapper.get_latest_proof_account(35).unwrap();

        let aptos_transaction = proof_assets.transaction();
        let aptos_transaction_bytes = bcs::to_bytes(aptos_transaction).unwrap();

        let lc_transaction = TransactionInfo::from_bytes(&aptos_transaction_bytes).unwrap();

        assert_eq!(
            LcCryptoHash::hash(&lc_transaction).as_ref(),
            AptosCryptoHash::hash(aptos_transaction).as_ref()
        );
    }
}
