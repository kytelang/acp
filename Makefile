.PHONY: build test transparency fmt clippy check

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace

# M1 golden transparency + anti-bypass harness (reused by later milestones).
test-transparency:
	cargo test -p acp-proxy --test m1_transparency

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt clippy build test

sbom: ## generate CycloneDX SBOM (offline)
	bash scripts/sbom.sh
