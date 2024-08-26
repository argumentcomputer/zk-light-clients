.PHONY: benchmark bench-ci

benchmark:
	@read -p "Enter benchmark name: " bench; \
	RUSTFLAGS="-C target-cpu=native -C opt-level=3" \
	SHARD_SIZE=4194304 \
	SHARD_CHUNKING_MULTIPLIER=256 \
	cargo bench --features ethereum --bench $$bench

BENCH ?= committee_change

bench-ci:
	cargo bench --features ethereum --bench $(BENCH)
