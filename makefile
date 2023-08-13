default:
	cargo run -q

version:
	cargo run -q -- --version

release:
	cargo build -r

install:
	cargo install --path .

watch:
	cargo watch -c -x clippy

run-example:
	cargo build --release
	sh -c "cd example && ../target/release/tic"

run-example-debug:
	cargo build
	sh -c "cd example && ../target/debug/tic"
