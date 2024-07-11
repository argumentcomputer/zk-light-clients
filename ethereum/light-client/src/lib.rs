// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Light Client
//!
//! This crate provides the light client implementation for the Ethereum network. The light client
//! is responsible for fetching the data necessary to prove sync committee changes and value inclusion
//! in the state of the Ethereum network, and to leverage this data to generate proofs for them using
//! Sphinx.
//!
//! ## Binaries
//!
//! The light client is divided in 3 main components:
//! - `client`: A client that can be used to coordinate data fetching from an Ethereum 2.0 Beacon Node
//!   and an execution RPC provider.
//! - `server_primary`: The main entrypoint for our proof server, in charge of load balancing the
//!   incoming requests and handling proofs about state inclusion.
//! - `server_secondary`: A secondary server that is in charge of handling proof generation for sync
//!   committee changes.
//!
//! ## Library
//!
//! The library provides the types and utilities necessary to interact build the binaries of the light
//! client. It has the following modules:
//! - [`client`] : The client that can be used to coordinate data fetching from the remote services.
//! - [`proofs`]: The utilities to generate and verify proofs for the light client.
//! - [`types`]: Types and utilities to leverage data from the remote services.
//!
//! For more detailed information, users should refer to the specific documentation for each
//! sub-module.

pub mod client;
pub mod proofs;
pub mod types;
