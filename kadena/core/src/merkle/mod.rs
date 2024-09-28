// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

pub mod proof;
pub mod spv;
pub mod subject;

/// Tag associated to the chain ID value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const CHAIN_ID_TAG: u16 = 0x0002;

/// Tag associated to the block height value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const BLOCK_HEIGHT_TAG: u16 = 0x0003;

/// Tag associated to the block weight value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const BLOCK_WEIGHT_TAG: u16 = 0x0004;

/// Tag associated to the feature flags value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const FEATURE_FLAGS_TAG: u16 = 0x0006;

/// Tag associated to the block creation time in the Merkle tree.
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const BLOCK_CREATION_TIME_TAG: u16 = 0x0007;

/// Tag associated to the Chainweb version value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const CHAINWEB_VERSION_TAG: u16 = 0x0008;

/// Tag associated to the target PoW hash value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const HASH_TARGET_TAG: u16 = 0x0011;

/// Tag associated to a transaction value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const TRANSACTION_TAG: u16 = 0x0013;

/// Tag associated to the epoch start value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const EPOCH_START_TIME_TAG: u16 = 0x0019;

/// Tag associated to the block nonce value in the Merkle tree.
///
/// See [the `chainweb-node` wiki](https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function).
pub const BLOCK_NONCE_TAG: u16 = 0x0020;
