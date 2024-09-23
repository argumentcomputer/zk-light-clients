// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::error::CryptoError;
use crate::crypto::hash::sha512::hash_inner;
use crate::crypto::hash::HashValue;
use crate::crypto::U256;
use crate::types::adjacent::ADJACENT_PARENT_RAW_BYTES_LENGTH;
use crate::types::error::{TypesError, ValidationError};
use crate::types::graph::{TWENTY_CHAIN_GRAPH, TWENTY_CHAIN_GRAPH_DEGREE};
use crate::types::header::chain::{
    KadenaHeaderRaw, CHAIN_BYTES_LENGTH, RAW_HEADER_DECODED_BYTES_LENGTH,
};
use crate::types::{U16_BYTES_LENGTH, U64_BYTES_LENGTH};
use anyhow::Result;
use getset::Getters;
use std::cmp::Ordering;

/// A layer header for a Chainweb network. It contains the height of the layer and the headers of
/// all the chains in the Chainweb network at the given height.
#[derive(Debug, Clone, Eq, PartialEq, Getters)]
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
    pub fn new(height: u64, chain_headers: Vec<KadenaHeaderRaw>) -> Result<Self, ValidationError> {
        if chain_headers.is_empty() {
            return Err(ValidationError::InvalidChainBlockHeadersList);
        }

        Ok(Self {
            height,
            chain_headers,
        })
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
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TypesError> {
        let height = u64::from_le_bytes(bytes[..U64_BYTES_LENGTH].try_into().unwrap());
        bytes = &bytes[U64_BYTES_LENGTH..];

        let headers_vec_len =
            u16::from_le_bytes(bytes[..U16_BYTES_LENGTH].try_into().unwrap()) as usize;
        bytes = &bytes[U16_BYTES_LENGTH..];

        let expected_len = headers_vec_len * RAW_HEADER_DECODED_BYTES_LENGTH;

        // Error handling for overlength and underlength cases
        match bytes.len().cmp(&expected_len) {
            Ordering::Greater => Err(TypesError::OverLength {
                structure: "ChainwebLayerHeader".to_string(),
                maximum: U64_BYTES_LENGTH + U16_BYTES_LENGTH + expected_len,
                actual: bytes.len(),
            }),
            Ordering::Less => Err(TypesError::UnderLength {
                structure: "ChainwebLayerHeader".to_string(),
                minimum: U64_BYTES_LENGTH + U16_BYTES_LENGTH + expected_len,
                actual: bytes.len(),
            }),
            Ordering::Equal => {
                let mut chain_headers: Vec<KadenaHeaderRaw> = Vec::with_capacity(headers_vec_len);
                for _ in 0..headers_vec_len {
                    let header =
                        KadenaHeaderRaw::from_bytes(&bytes[..RAW_HEADER_DECODED_BYTES_LENGTH])?;
                    chain_headers.push(header);
                    bytes = &bytes[RAW_HEADER_DECODED_BYTES_LENGTH..];
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
    pub fn deserialize_list(mut bytes: &[u8]) -> Result<Vec<Self>, TypesError> {
        // Ensure we have enough bytes for the length of the list
        if bytes.len() < U16_BYTES_LENGTH {
            return Err(TypesError::UnderLength {
                structure: "Vec<ChainwebLayerHeader>".to_string(),
                minimum: U16_BYTES_LENGTH,
                actual: bytes.len(),
            });
        }

        // Read the length of the list
        let list_len = u16::from_le_bytes(bytes[..U16_BYTES_LENGTH].try_into().unwrap()) as usize;
        bytes = &bytes[U16_BYTES_LENGTH..];

        let mut list: Vec<Self> = Vec::with_capacity(list_len);

        for _ in 0..list_len {
            // Ensure we have enough bytes for the next item size
            if bytes.len() < U16_BYTES_LENGTH {
                return Err(TypesError::UnderLength {
                    structure: "Vec<ChainwebLayerHeader>".to_string(),
                    minimum: U16_BYTES_LENGTH,
                    actual: bytes.len(),
                });
            }

            // Read the size of the next item
            let size = u16::from_le_bytes(bytes[..U16_BYTES_LENGTH].try_into().unwrap()) as usize;
            bytes = &bytes[U16_BYTES_LENGTH..];

            // Ensure we have enough bytes for the full item
            if bytes.len() < size {
                return Err(TypesError::UnderLength {
                    structure: "Vec<ChainwebLayerHeader>".to_string(),
                    minimum: size,
                    actual: bytes.len(),
                });
            }

            // Deserialize the item and add it to the list
            let header = Self::from_bytes(&bytes[..size])?;
            list.push(header);

            // Consume the bytes for this item
            bytes = &bytes[size..];
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
    pub fn cumulative_produced_work<I>(headers: I) -> Result<U256, ValidationError>
    where
        I: IntoIterator<Item = Self>,
    {
        headers
            .into_iter()
            .map(|header| header.produced_work())
            .try_fold(U256::zero(), |acc, work| work.map(|w| acc + w))
    }

    /// Get the root of the headers in the layer.
    ///
    /// # Returns
    ///
    /// The root of the headers in the layer.
    ///
    /// # Notes
    ///
    /// When the  chain graph degree changes along with the [`crate::types::graph::TWENTY_CHAIN_GRAPH_DEGREE`]
    /// constant this method should be updated.
    pub fn header_root(&self) -> Result<HashValue, CryptoError> {
        let mut hashes = self
            .chain_headers()
            .iter()
            .map(|header| HashValue::new(*header.hash()))
            .collect::<Vec<_>>();

        // Balance the tree
        hashes.resize(hashes.len().next_power_of_two(), HashValue::new([0; 32]));

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

        let mut confirmation_work = U256::zero();
        for (i, layer_header) in list.iter().enumerate() {
            for (j, chain_header) in layer_header.chain_headers().iter().enumerate() {
                if u64::from_le_bytes(*chain_header.height()) != *layer_header.height() {
                    return Err(ValidationError::InvalidChainBlockHeight {
                        chain_height: u64::from_le_bytes(*chain_header.height()),
                        layer_height: *layer_header.height(),
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
                if let Some(previous_layer) = list.get(i.wrapping_sub(1)) {
                    let parent_chain_header = previous_layer
                        .chain_headers()
                        .get(j)
                        .ok_or_else(|| ValidationError::MissingParentHeader { index: j })?;

                    if chain_header.parent() != parent_chain_header.hash() {
                        return Err(ValidationError::InvalidParentHash {
                            computed: HashValue::new(*chain_header.parent()),
                            stored: HashValue::new(*parent_chain_header.hash()),
                        });
                    }
                }

                // Check that the adjacent record are for the correct chains
                let mut adjacent_chain_records = Vec::with_capacity(TWENTY_CHAIN_GRAPH_DEGREE);
                for i in 0..TWENTY_CHAIN_GRAPH_DEGREE {
                    let start = U16_BYTES_LENGTH + i * ADJACENT_PARENT_RAW_BYTES_LENGTH;
                    let end = start + CHAIN_BYTES_LENGTH;
                    adjacent_chain_records.push(u32::from_le_bytes(chain_header.adjacents().get(start..end)
                        .expect("Should be able to get adjacent chain value")
                        .try_into()
                        .expect("Should be able to convert adjacent chain value to fixed length array"))
                    );
                }
                adjacent_chain_records.sort();

                let chain = u32::from_le_bytes(*chain_header.chain()) as usize;
                if adjacent_chain_records != TWENTY_CHAIN_GRAPH[chain] {
                    return Err(ValidationError::InvalidAdjacentChainRecords {
                        layer: layer_header.height as usize,
                        chain,
                    });
                }
            }

            // Compute cumulative work
            let produced_work = layer_header.produced_work()?;

            if i > target_block_idx {
                confirmation_work += produced_work;
            }
        }

        // Retrieve the root hashes for the first and target headers
        let first_header_root = list[0]
            .header_root()
            .map_err(|err| ValidationError::HashError { source: err.into() })?;

        let target_header_root = list[target_block_idx]
            .header_root()
            .map_err(|err| ValidationError::HashError { source: err.into() })?;

        Ok((first_header_root, target_header_root, confirmation_work))
    }
}

#[cfg(all(test, feature = "kadena"))]
mod test {
    use super::*;
    use crate::test_utils::{get_layer_block_headers, RAW_HEADER};

    #[test]
    fn test_serde_chainweb_layer_header() {
        let header = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();
        let layer_header =
            ChainwebLayerHeader::new(1, vec![KadenaHeaderRaw::default(), header]).unwrap();

        let bytes = layer_header.to_bytes();
        let deserialized = ChainwebLayerHeader::from_bytes(&bytes).unwrap();

        assert_eq!(layer_header, deserialized);
    }

    #[test]
    fn test_serde_list_chainweb_layer_header() {
        let header = KadenaHeaderRaw::from_base64(RAW_HEADER).unwrap();
        let layer_header =
            ChainwebLayerHeader::new(1, vec![KadenaHeaderRaw::default(), header]).unwrap();

        let list = vec![layer_header.clone(), layer_header];

        let bytes = ChainwebLayerHeader::serialize_list(&list);
        let deserialized = ChainwebLayerHeader::deserialize_list(&bytes).unwrap();

        assert_eq!(list, deserialized);
    }

    #[test]
    fn test_verify_layer_block_header_list_no_panic() {
        let headers = get_layer_block_headers();

        let (first_hash, target_hash, confirmation_work) =
            ChainwebLayerHeader::verify(&headers).unwrap();

        assert_eq!(first_hash, headers[0].header_root().unwrap());
        assert_eq!(
            target_hash,
            headers[headers.len() / 2].header_root().unwrap()
        );
        assert_eq!(
            confirmation_work,
            ChainwebLayerHeader::cumulative_produced_work(
                headers[headers.len() / 2..headers.len() - 1].to_vec()
            )
            .unwrap()
        );
    }

    fn hash_list(mut list: Vec<HashValue>) -> HashValue {
        while list.len() > 1 {
            list = list
                .chunks(2)
                .map(|pair| hash_inner(pair[0].as_ref(), pair[1].as_ref()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        }

        list[0]
    }

    #[test]
    fn test_layer_root_no_chain_headers() {
        assert!(ChainwebLayerHeader::new(1, vec![]).is_err());
    }

    #[test]
    fn test_layer_root_chain_headers_pwr_of_two() {
        let layer_header =
            ChainwebLayerHeader::new(1, vec![KadenaHeaderRaw::default(); 4]).unwrap();

        let layer_root = layer_header.header_root().unwrap();
        let expected_root = hash_list(
            layer_header
                .chain_headers
                .iter()
                .map(|h| HashValue::new(*h.hash()))
                .collect(),
        );

        assert_eq!(layer_root, expected_root);
    }

    #[test]
    fn test_layer_root_chain_headers_not_pwr_of_two() {
        let layer_header =
            ChainwebLayerHeader::new(1, vec![KadenaHeaderRaw::default(); 3]).unwrap();

        let layer_root = layer_header.header_root().unwrap();

        let mut list_hashed = layer_header
            .chain_headers
            .iter()
            .map(|h| HashValue::new(*h.hash()))
            .collect::<Vec<HashValue>>();
        list_hashed.push(HashValue::new([0; 32]));
        let expected_root = hash_list(list_hashed);

        assert_eq!(layer_root, expected_root);
    }
}
