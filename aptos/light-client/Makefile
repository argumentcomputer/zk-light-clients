.PHONY: benchmark bench-ci

benchmark:
	@read -p "Enter benchmark name: " bench; \
	RUST_LOG="debug" \
	RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native" \
	cargo +nightly bench --features aptos --bench $$bench

BENCH ?= e2e

bench-ci:
	RUST_LOG="info" \
	RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native" \
	cargo +nightly bench --features aptos --bench $(BENCH)
