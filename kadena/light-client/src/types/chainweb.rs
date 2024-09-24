// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use getset::Getters;
use kadena_lc_core::merkle::proof::MerkleProof;
use kadena_lc_core::merkle::spv::Spv;
use kadena_lc_core::merkle::subject::Subject;
use kadena_lc_core::types::error::TypesError;
use kadena_lc_core::types::header::chain::KadenaHeaderRaw;
use serde::Deserialize;

const REQUEST_KEY_PROPERTY: &str = "reqKey";

/// Response received while querying block headers from a Chainweb
/// node.
#[derive(Clone, Debug, Deserialize, Getters)]
#[allow(dead_code)]
#[getset(get = "pub")]
pub struct BlockHeaderResponse {
    next: String,
    items: Vec<String>,
    limit: usize,
}

impl TryInto<Vec<KadenaHeaderRaw>> for BlockHeaderResponse {
    type Error = TypesError;

    fn try_into(self) -> Result<Vec<KadenaHeaderRaw>, Self::Error> {
        self.items
            .into_iter()
            .map(|item| KadenaHeaderRaw::from_base64(&item.into_bytes()))
            .collect()
    }
}

/// Response received while querying an SPV proof from a Chainweb
/// node.
#[derive(Clone, Debug, Deserialize)]
pub struct SpvResponse {
    algorithm: String,
    chain: u32,
    pub object: String,
    pub subject: EncodedSubject,
}

/// Encoded subject.
#[derive(Clone, Debug, Deserialize)]
pub struct EncodedSubject {
    pub input: String,
}

impl TryInto<Spv> for SpvResponse {
    type Error = TypesError;

    fn try_into(self) -> Result<Spv, Self::Error> {
        let object = MerkleProof::from_base64(&self.object.into_bytes())?;
        let subject = Subject::new(self.subject.input);

        Ok(Spv::new(self.algorithm, self.chain, object, subject))
    }
}

/// Response received while querying a Payload from a Chainweb
/// node.
#[derive(Clone, Debug, Deserialize, Getters)]
#[serde(rename_all = "camelCase")]
#[getset(get = "pub")]
pub struct PayloadResponse {
    coinbase: String,
    miner_data: String,
    outputs_hash: String,
    payload_hash: String,
    transactions: Vec<Vec<String>>,
    transactions_hash: String,
}

impl PayloadResponse {
    /// Get the transaction request key for the given transaction index.
    ///
    /// # Arguments
    ///
    /// * `transaction_index` - The index of the transaction.
    ///
    /// # Returns
    ///
    /// The transaction request key.
    pub fn get_transaction_request_key(&self, transaction_index: usize) -> Result<String> {
        let output_bytes = URL_SAFE_NO_PAD
            .decode(
                self.transactions()
                    .get(transaction_index)
                    .ok_or_else(|| anyhow!("Transaction index out of bounds"))?
                    .get(1)
                    .ok_or_else(|| anyhow!("Transaction output not found"))?
                    .as_bytes(),
            )
            .map_err(|err| anyhow!("Error decoding transaction output: {}", err))?;

        let json_value = serde_json::from_slice::<serde_json::Value>(&output_bytes)
            .map_err(|err| anyhow!("Error deserializing transaction output: {}", err))?;

        json_value
            .get(REQUEST_KEY_PROPERTY)
            .ok_or_else(|| anyhow!("Request key not found in transaction output"))
            .and_then(|value| {
                value
                    .as_str()
                    .ok_or_else(|| anyhow!("Request key is not a string"))
            })
            .map(|value| value.to_string())
    }
}
