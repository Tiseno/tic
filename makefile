default:
	cargo run -q

release:
	cargo build -r

install:
	cargo install --path .

watch:
	cargo watch -c -x clippy

run-example:
	cargo build
	sh -c "cd example && ../target/debug/tic"
