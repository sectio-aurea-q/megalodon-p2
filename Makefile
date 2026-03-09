# MEGALODON P2 — Process Memory Secret Scanner
# ==============================================

.PHONY: build run list clean

build:
	@echo "[*] Building meg-scan..."
	cargo build --release
	@echo "[*] Done: ./target/release/meg-scan"

run: build
	@echo "[*] Scanning all known secure applications..."
	sudo ./target/release/meg-scan --all --json --verbose

list: build
	@echo "[*] Listing target processes..."
	sudo ./target/release/meg-scan --list

clean:
	cargo clean
	rm -rf results/
