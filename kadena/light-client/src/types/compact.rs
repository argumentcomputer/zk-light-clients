// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kadena_lc_core::crypto::hash::DIGEST_BYTES_LENGTH;
use kadena_lc_core::types::error::TypesError;
use kadena_lc_core::types::header::chain::{CompactHeaderRaw, KadenaHeaderRaw};
use serde::Deserialize;

/// Response received while querying compact headers from a Chainweb
#[derive(Clone, Debug, Deserialize)]
struct CompactLayerResponse {
    base: Vec<String>,
    layers: Vec<Vec<String>>,
    hashes: Vec<String>,
}

/// Decoded compact header in Rust types.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct CompactLayerDecoded {
    base: Vec<KadenaHeaderRaw>,
    layers: Vec<Vec<CompactHeaderRaw>>,
    hashes: Vec<[u8; 32]>,
}

impl TryFrom<CompactLayerResponse> for CompactLayerDecoded {
    type Error = TypesError;

    fn try_from(value: CompactLayerResponse) -> Result<Self, Self::Error> {
        let base = value
            .base
            .into_iter()
            .map(|base| KadenaHeaderRaw::from_base64(&base.into_bytes()))
            .collect::<Result<_, _>>()?;

        let layers = value
            .layers
            .into_iter()
            .map(|layer| {
                layer
                    .into_iter()
                    .map(|compact| CompactHeaderRaw::from_base64(&compact.into_bytes()))
                    .collect::<Result<_, TypesError>>()
            })
            .collect::<Result<_, TypesError>>()?;

        let hashes = value
            .hashes
            .into_iter()
            .map(|hash| {
                let decoded = URL_SAFE_NO_PAD.decode(hash.as_bytes()).map_err(|err| {
                    TypesError::DeserializationError {
                        structure: "hashes".to_string(),
                        source: err.into(),
                    }
                })?;
                <[u8; DIGEST_BYTES_LENGTH]>::try_from(decoded).map_err(|_| {
                    TypesError::DeserializationError {
                        structure: "hashes".to_string(),
                        source: "Decoded hash length is not 32 bytes.".into(),
                    }
                })
            })
            .collect::<Result<Vec<_>, TypesError>>()?;

        Ok(Self {
            base,
            layers,
            hashes,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::types::compact::{CompactLayerDecoded, CompactLayerResponse};
    use kadena_lc_core::test_utils::get_compact_headers_bytes;

    #[test]
    fn test_deserialize_compact_response() {
        let bytes = get_compact_headers_bytes();

        let response: CompactLayerResponse = serde_json::from_slice(&bytes).unwrap();

        let _ = CompactLayerDecoded::try_from(response).unwrap();
    }
}
