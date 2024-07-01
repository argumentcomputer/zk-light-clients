.PHONY: benchmark bench-ci

benchmark:
	@read -p "Enter benchmark name: " bench; \
	RUST_LOG="debug" \
	RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native -C opt-level=3" \
	SHARD_BATCH_SIZE=0 \
	cargo +nightly-2024-05-31 bench --bench $$bench

BENCH ?= e2e

bench-ci:
	RUST_LOG="info" \
	RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native -C opt-level=3" \
	SHARD_BATCH_SIZE=0 \
	cargo +nightly-2024-05-31 bench --bench $(BENCH)
