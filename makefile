default:
	cargo run

release:
	cargo build -r

watch:
	cargo watch -c -x clippy
