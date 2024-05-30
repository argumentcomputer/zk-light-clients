// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

pub mod error;
pub mod types;
pub mod utils;

/// Endpoint of the Aptos node to fetch the current ledger info.
pub const APTOS_LEDGER_INFO_ENDPOINT: &str = "v1/";

/// Endpoint of the Aptos node to fetch the epoch change proof.
pub const APTOS_EPOCH_CHANGE_PROOF_ENDPOINT: &str = "v1/epoch/proof";

pub fn aptos_inclusion_proof_endpoint(address: &str) -> String {
    format!("v1/accounts/{address}/proof")
}
