// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0, MIT

//! # Proof Server
//!
//! This crate provides the proof server implementation for the Aptos node. The proof server is
//! responsible for serving proofs to clients that need to verify the state of the ledger.
//!
//! ## Design
//!
//! To provide the full functionalities of a Light Client the proof server is divided in 3 main
//! components:
//! - [`client`]: A client that can be used to coordinate data fetching from an
//! Aptos Public Full Node and the proof server.
//! - [primary server](./bin/server_primary.rs): The main entrypoint for our proof server, in charge
//! of load balancing the incoming requests and handling proofs about account inclusion.
//! - [secondary server](./bin/server_secondary.rs): A secondary server that is in charge of handling
//! requests about epoch changes.

/// Module containing the errors that can be thrown while using the client and the proof server.
pub mod error;
/// Module containing the types encountered while fetching data from an Aptos Public Full Node and
/// interacting with the proof server.
pub mod types;
/// Module containing some utilities.
pub mod utils;

/// Endpoint of the Aptos node to fetch the current ledger info.
pub const APTOS_LEDGER_INFO_ENDPOINT: &str = "v1/";

/// Endpoint of the Aptos node to fetch the epoch change proof.
pub const APTOS_EPOCH_CHANGE_PROOF_ENDPOINT: &str = "v1/epoch/proof";

/// Generates the endpoint to fetch the inclusion proof for a given address.
pub fn aptos_inclusion_proof_endpoint(address: &str) -> String {
    format!("v1/accounts/{address}/proof")
}
