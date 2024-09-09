// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::sha512::hash_inner;
use crate::crypto::hash::HashValue;
use crate::crypto::U256;
use crate::types::error::{TypesError, ValidationError};
use crate::types::header::chain::{KadenaHeaderRaw, RAW_HEADER_DECODED_BYTES_LENGTH};
use crate::types::{U16_BYTES_LENGTH, U64_BYTES_LENGTH};
use anyhow::Result;
use getset::Getters;
use std::cmp::Ordering;

/// A layer header for a Chainweb network. It contains the height of the layer and the headers of
/// all the chains in the Chainweb network at the given height.
#[derive(Debug, Clone, Default, Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct ChainwebLayerHeader {
    height: u64,
    chain_headers: Vec<KadenaHeaderRaw>,
}

impl ChainwebLayerHeader {
    /// Create a new `ChainwebLayerHeader` with the given height and chain headers.
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the layer.
    /// * `chain_headers` - The headers of all the chains in the Chainweb network at the given height.
    ///
    /// # Returns
    ///
    /// A new `ChainwebLayerHeader`.
    pub const fn new(height: u64, chain_headers: Vec<KadenaHeaderRaw>) -> Self {
        Self {
            height,
            chain_headers,
        }
    }

    /// Get the total amount of work produced by all the chains in the layer.
    ///
    /// # Returns
    ///
    /// The total amount of work produced by all the chains in the layer.
    pub fn produced_work(&self) -> Result<U256, ValidationError> {
        self.chain_headers
            .iter()
            .try_fold(U256::zero(), |acc, header| {
                header.produced_work().map(|work| acc + work)
            })
    }

    /// Serialized a `ChainwebLayerHeader` into a byte vector.
    ///
    /// # Returns
    ///
    /// A byte vector containing the serialized `ChainwebLayerHeader`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&(self.chain_headers.len() as u16).to_le_bytes());
        for header in &self.chain_headers {
            bytes.extend_from_slice(&header.to_bytes());
        }
        bytes
    }

    /// Deserialize a `ChainwebLayerHeader` from a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte vector to deserialize.
    ///
    /// # Returns
    ///
    /// A `ChainwebLayerHeader` deserialized from the byte vector.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let mut offset = 0;

        let height =
            u64::from_le_bytes(bytes[offset..offset + U64_BYTES_LENGTH].try_into().unwrap());
        offset += U64_BYTES_LENGTH;

        let headers_vec_len =
            u16::from_le_bytes(bytes[offset..offset + U16_BYTES_LENGTH].try_into().unwrap())
                as usize;
        offset += U16_BYTES_LENGTH;

        match bytes
            .len()
            .cmp(&(offset + headers_vec_len * RAW_HEADER_DECODED_BYTES_LENGTH))
        {
            Ordering::Greater => Err(TypesError::OverLength {
                structure: "ChainwebLayerHeader".to_string(),
                maximum: offset + headers_vec_len * RAW_HEADER_DECODED_BYTES_LENGTH,
                actual: bytes.len(),
            }),
            Ordering::Less => Err(TypesError::UnderLength {
                structure: "ChainwebLayerHeader".to_string(),
                minimum: offset + headers_vec_len * RAW_HEADER_DECODED_BYTES_LENGTH,
                actual: bytes.len(),
            }),
            Ordering::Equal => {
                let mut chain_headers: Vec<KadenaHeaderRaw> = Vec::with_capacity(headers_vec_len);

                for _ in 0..headers_vec_len {
                    let header = KadenaHeaderRaw::from_bytes(
                        &bytes[offset..offset + RAW_HEADER_DECODED_BYTES_LENGTH],
                    )?;
                    chain_headers.push(header);
                    offset += RAW_HEADER_DECODED_BYTES_LENGTH;
                }

                Ok(Self {
                    height,
                    chain_headers,
                })
            }
        }
    }

    /// Serialize a list of `ChainwebLayerHeader`s into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `list` - The list of `ChainwebLayerHeader`s to serialize.
    ///
    /// # Returns
    ///
    /// A byte vector containing the serialized list of `ChainwebLayerHeader`s.
    pub fn serialize_list(list: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(list.len() as u16).to_le_bytes());
        for header in list {
            let layer_bytes = header.to_bytes();
            bytes.extend_from_slice(&(layer_bytes.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&layer_bytes);
        }
        bytes
    }

    /// Deserialize a list of `ChainwebLayerHeader`s from a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte vector to deserialize.
    ///
    /// # Returns
    ///
    /// A list of `ChainwebLayerHeader`s deserialized from the byte vector.
    pub fn deserialize_list(bytes: &[u8]) -> Result<Vec<Self>, TypesError> {
        let mut offset = 0;

        if bytes.len() < U16_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "Vec<ChainwebLayerHeader>".to_string(),
                minimum: U16_BYTES_LENGTH,
                actual: bytes.len(),
            });
        }

        let list_len =
            u16::from_le_bytes(bytes[offset..offset + U16_BYTES_LENGTH].try_into().unwrap())
                as usize;
        offset += U16_BYTES_LENGTH;

        let mut list: Vec<Self> = Vec::with_capacity(list_len);

        for _ in 0..list_len {
            if offset + U16_BYTES_LENGTH > bytes.len() {
                return Err(TypesError::UnderLength {
                    structure: "Vec<ChainwebLayerHeader>".to_string(),
                    minimum: offset + U16_BYTES_LENGTH,
                    actual: bytes.len(),
                });
            }

            let size =
                u16::from_le_bytes(bytes[offset..offset + U16_BYTES_LENGTH].try_into().unwrap())
                    as usize;
            offset += U16_BYTES_LENGTH;

            if offset + size > bytes.len() {
                return Err(TypesError::UnderLength {
                    structure: "Vec<ChainwebLayerHeader>".to_string(),
                    minimum: offset + size,
                    actual: bytes.len(),
                });
            }

            let header = Self::from_bytes(&bytes[offset..offset + size])?;
            list.push(header);
            offset += size;
        }

        Ok(list)
    }

    /// Get the cumulative amount of work produced by all the chains in the list of layer headers.
    ///
    /// # Arguments
    ///
    /// * `list` - The list of layer headers.
    ///
    /// # Returns
    ///
    /// The cumulative amount of work produced by all the chains in the list of layer headers.
    pub fn cumulative_produced_work(list: &[Self]) -> Result<U256, ValidationError> {
        list.iter().try_fold(U256::zero(), |acc, header| {
            header.produced_work().map(|work| acc + work)
        })
    }

    /// Get the root of the headers in the layer.
    ///
    /// # Returns
    ///
    /// The root of the headers in the layer.
    pub fn header_root(&self) -> Result<HashValue, CryptoError> {
        let mut hashes = self
            .chain_headers()
            .iter()
            .map(|header| HashValue::new(*header.hash()))
            .collect::<Vec<_>>();

        // Balance the tree
        while !hashes.len().is_power_of_two() {
            hashes.push(HashValue::new([0; 32]));
        }

        // Hash pairs of intermediate nodes until only one hash remains (the root)
        while hashes.len() > 1 {
            hashes = hashes
                .chunks(2)
                .map(|pair| hash_inner(pair[0].as_ref(), pair[1].as_ref()))
                .collect::<Result<Vec<_>, _>>()?;
        }

        // The last remaining hash is the root
        Ok(hashes[0])
    }

    pub fn verify(list: &[Self]) -> Result<(HashValue, HashValue, U256), ValidationError> {
        // Ensure input list is valid
        if list.len() < 3 || list.len() % 2 != 1 {
            return Err(ValidationError::InvalidLayerBlockHeadersList { size: list.len() });
        }

        // Target block has central position in the list of headers
        let target_block_idx = list.len() / 2;

        let mut confirmation_work = U256::from(0);
        for i in 0..list.len() {
            for (j, chain_header) in list[i].chain_headers().iter().enumerate() {
                if u64::from_le_bytes(*chain_header.height()) != *list[i].height() {
                    return Err(ValidationError::InvalidChainBlockHeight {
                        chain_height: u64::from_le_bytes(*chain_header.height()),
                        layer_height: *list[i].height(),
                    });
                }

                let chain_header_hash = chain_header
                    .header_root()
                    .map_err(|err| ValidationError::HashError { source: err.into() })?;

                // Check stored hash is correct
                if chain_header_hash.as_ref() != chain_header.hash() {
                    return Err(ValidationError::InvalidChainBlockHash {
                        computed: chain_header_hash,
                        stored: HashValue::new(*chain_header.hash()),
                    });
                }

                // Check that parent is right
                if i > 0 {
                    let parent = list[i - 1]
                        .chain_headers()
                        .get(j)
                        .expect("Should be able to get the parent header");

                    if chain_header.parent() != parent.hash() {
                        return Err(ValidationError::InvalidParentHash {
                            computed: HashValue::new(*chain_header.parent()),
                            stored: HashValue::new(*parent.hash()),
                        });
                    }
                }
            }

            // Compute cumulative work
            let produced_work = list[i].produced_work()?;

            if i > target_block_idx {
                confirmation_work += produced_work;
            }
        }

        Ok((
            list[0]
                .header_root()
                .map_err(|err| ValidationError::HashError { source: err.into() })?,
            list[target_block_idx]
                .header_root()
                .map_err(|err| ValidationError::HashError { source: err.into() })?,
            confirmation_work,
        ))
    }
}

#[cfg(all(test, feature = "kadena"))]
mod test {
    use super::*;
    use crate::test_utils::{get_layer_block_headers, RAW_HEADER};

    #[test]
    fn test_serde_chainweb_layer_header() {
        let header = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();
        let layer_header = ChainwebLayerHeader::new(1, vec![KadenaHeaderRaw::default(), header]);

        let bytes = layer_header.to_bytes();
        let deserialized = ChainwebLayerHeader::from_bytes(&bytes).unwrap();

        assert_eq!(layer_header, deserialized);
    }

    #[test]
    fn test_serde_list_chainweb_layer_header() {
        let header = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();
        let layer_header = ChainwebLayerHeader::new(1, vec![KadenaHeaderRaw::default(), header]);

        let list = vec![layer_header.clone(), layer_header];

        let bytes = ChainwebLayerHeader::serialize_list(&list);
        let deserialized = ChainwebLayerHeader::deserialize_list(&bytes).unwrap();

        assert_eq!(list, deserialized);
    }

    #[test]
    fn test_verify_layer_block_header_list_no_panic() {
        let headers = get_layer_block_headers();

        ChainwebLayerHeader::verify(&headers).unwrap();
    }
}
