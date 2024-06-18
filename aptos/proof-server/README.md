# Aptos Light Client Proof Server

This server supports parallel generation of inclusion and epoch change proofs for the Aptos Light Client as well as
verification for those proofs.

Internally, it's (currently) implemented as two servers that work in tandem.

* The *primary server* is capable of handling requests related to inclusion proofs internally;
* Requests related to epoch change proofs are handled by the *secondary server*

However, a client just needs to interact with the primary server directly.

To run the Light Client binaries or its end-to-end benchmarks, please refer to their dedicated sections in the mdBook.
You can find how to run the mdBook in the [README](../README.md). Otherwise, you can find the dedicated markdown files
in
the [`docs/src/run`](../docs/src/run/overview.md) or [`docs/src/benchmark`](../docs/src/benchmark/overview.md)
folder.