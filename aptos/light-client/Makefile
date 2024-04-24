.PHONY: benchmark

benchmark:
	@read -p "Enter benchmark name: " bench; \
	RUST_LOG="debug" \
	RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native" \
	cargo +nightly criterion --features aptos --bench $$bench