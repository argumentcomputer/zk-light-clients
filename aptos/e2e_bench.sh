#!/usr/bin/env bash

# 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576 2097152 4194304 8388608 16777216

#for reconstruct_commitments in "true" "false"
#do
  for shard_chunking_multiplier in 8 16 32 64 128 256
  do
    for shard_batch_size in 8 16 32 64 128 256
    do
      #for shard_size in 524288 1048576 2097152 4194304
      #do
        SHARD_SIZE=4194304 \
        SHARD_BATCH_SIZE=$shard_batch_size \
        RECONSTRUCT_COMMITMENTS=false \
        SHARD_CHUNKING_MULTIPLIER=$shard_chunking_multiplier \
        SNARK=1 \
        RUST_LOG=warn \
        RUSTFLAGS="-C target-cpu=native --cfg tokio_unstable -C opt-level=3" \
        PRIMARY_ADDR="127.0.0.1:8080" \
        SECONDARY_ADDR="127.0.0.1:8081" \
        cargo +nightly-2024-05-31 bench --bench proof_server
      #done
    done
  done
#done

# To run this script you need to specify what Rust test/bench to execute. Ideally it should print single line as a result, for example: [sha-extend] prove_core took: 1.226047583s, compress took: 4.652434084s
# > bash e2e_bench.sh >> e2e_bench.txt
#
# Then to clean up the results:
# > cat e2e_bench.txt | grep -E '{'
