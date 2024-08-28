#!/usr/bin/env bash

for shard_chunking_multiplier in 8 16 32 64 128 256
do
  for shard_batch_size in 0 8 16 32 64 128 256
  do
      SHARD_BATCH_SIZE=$shard_batch_size \
      SHARD_CHUNKING_MULTIPLIER=$shard_chunking_multiplier \
      SHARD_SIZE=4194304 \
      RECONSTRUCT_COMMITMENTS=false \
      SNARK=1 \
      RUST_LOG=warn \
      RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3" \
      PRIMARY_ADDR="127.0.0.1:8080" \
      SECONDARY_ADDR="127.0.0.1:8081" \
      cargo +nightly-2024-05-31 bench --bench proof_server
  done
done

# To identify optimal proving parameters, run this script in detached mode on the particular benchmarking machine:
# > screen /bin/bash -c 'bash e2e_bench.sh >> e2e_bench.txt 2>&1'

# To clean up the output:
# > cat e2e_bench.txt | grep -E '{'
