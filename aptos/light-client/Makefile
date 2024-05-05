.PHONY: benchmark

benchmark:
	@read -p "Enter benchmark name: " bench; \
	RUST_LOG="debug" \
	RUSTFLAGS="--cfg tokio_unstable -C target-cpu=native" \
	cargo +nightly bench --features aptos --bench execute -- $$bench