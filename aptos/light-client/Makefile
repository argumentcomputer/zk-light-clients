.PHONY: benchmark bench-ci

benchmark:
	@read -p "Enter benchmark name: " bench; \
	RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native -C opt-level=3" \
	SHARD_SIZE=4194304 \
	SHARD_BATCH_SIZE=0 \
	SHARD_CHUNKING_MULTIPLIER=256 \
	RECONSTRUCT_COMMITMENTS=false \
	cargo bench --features aptos --bench $$bench

BENCH ?= e2e

bench-ci:
	cargo bench --features aptos --bench $(BENCH)
