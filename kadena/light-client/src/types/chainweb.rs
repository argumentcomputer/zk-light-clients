// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use getset::Getters;
use kadena_lc_core::merkle::proof::MerkleProof;
use kadena_lc_core::merkle::spv::Spv;
use kadena_lc_core::merkle::subject::Subject;
use kadena_lc_core::types::error::TypesError;
use kadena_lc_core::types::header::chain::KadenaHeaderRaw;
use serde::Deserialize;

/// Response received while querying block headers from a Chainweb
/// node.
#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
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

/// Response received while querying block payload from a Chainweb
/// node.
#[derive(Clone, Debug, Deserialize, Getters)]
#[serde(rename_all = "camelCase")]
#[getset(get = "pub")]
pub struct BlockPayloadResponse {
    coinbase: String,
    miner_data: String,
    outputs_hash: String,
    payload_hash: String,
    transactions: Vec<Vec<String>>,
    transactions_hash: String,
}

/// Response received while querying a SPV proof from a Chainweb
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
