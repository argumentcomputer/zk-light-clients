## End-to-end benchmarks

The end-to-end benchmark is meant to benchmark the time taken to send both of the proofs generation request to the Proof
Server, have a parallel computation happen and receive the two proofs back. This benchmark is meant to simulate the
worst case scenario where the client has to generate two proofs in parallel.

The benchmark can be found in
the [`proof-server`](https://github.com/lurk-lab/zk-light-clients/blob/dev/aptos/proof-server/benches/proof_server.rs)
crate. It can be run with the following command:

```bash
RUST_LOG="debug" RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable" PRIMARY_ADDR="127.0.0.1:8080" SECONDARY_ADDR="127.0.0.1:8081" cargo +nightly bench --bench proof_server
```

This benchmark will spawn the two servers locally and make two requests in parallel to them. This generates both proofs
at the same time in the same machine. It measures to main metrics for each proof:

- `e2e_proving_time`: Time taken to send both request to the Proof Server and generate both proofs.
- `inclusion_proof`:
    - `proving_time`: Time taken to generate the inclusion proof.
    - `request_response_proof_size`: Size of the proof returned by the server.
- `epoch_change_proof`:
    - `proving_time`: Time taken to generate the epoch change proof.
    - `request_response_proof_size`: Size of the proof returned by the server.

```json
{
  e2e_proving_time: 107678,
  inclusion_proof: {
    proving_time: 107678,
    request_response_proof_size: 20823443
  },
  epoch_change_proof: {
    proving_time: 125169,
    request_response_proof_size: 23088485
  }
}
```

> Note: As the proof server is run with the `RUST_LOG=debug` environment variable, it is also possible to grab the inner
> metrics from Sphinx.

## Groth16 proofs

To benchmark the end-to-end flow with Groth16 proofs, we first need to generate the circuits assets as described in [the
configuration section](./configuration.md). Then, just pass the environment variable `GROTH16=1`:

```bash
GROTH16=1 RUST_LOG="debug" RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable" PRIMARY_ADDR="127.0.0.1:8080" SECONDARY_ADDR="127.0.0.1:8081" cargo +nightly bench --bench proof_server
```