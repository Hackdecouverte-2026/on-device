# on-device: build, harden, sign and run workflow.
#
# Reads the proxy allowlist and signing public key from .env (same file the
# binary bundles at compile time). Secrets live under secrets/ (gitignored).

CARGO  ?= cargo
TARGET ?= target/release/on-device
SIGN   ?= target/release/sign
SECRET ?= secrets/sig_key.sig

# Pulls in SIGNING_PUBKEY (and PROXY) from .env; missing file is not fatal here
# (the `release` target below reports it clearly).
-include .env

.DEFAULT_GOAL := help

.PHONY: help build release keygen sign verify package run test lint fmt clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

.env:
	@echo "error: .env is missing; run 'cp .env.example .env' and fill it in" >&2
	@exit 1

build: ## Debug build
	$(CARGO) build

release: .env ## Optimized, stripped release build (LTO + obfuscation)
	$(CARGO) build --release

$(SIGN):
	$(CARGO) build --release --bin sign

keygen: $(SIGN) ## Generate a signing keypair into secrets/sig_key.sig (prints public key)
	@mkdir -p secrets
	$(SIGN) keygen $(SECRET)

sign: release $(SIGN) ## Sign the release binary with the secret key
	$(SIGN) sign $(TARGET) $(SECRET)

verify: $(SIGN) ## Verify the release binary against SIGNING_PUBKEY from .env
	@test -n "$(SIGNING_PUBKEY)" \
		|| { echo "error: SIGNING_PUBKEY is not set in .env" >&2; exit 1; }
	$(SIGN) verify $(TARGET) "$(SIGNING_PUBKEY)"

package: sign verify ## Build, sign and verify (full hardened artifact)

run: release ## Run the agent (proxy login on macOS needs admin)
	./$(TARGET)

test: ## Run the test suite
	$(CARGO) test

lint: ## Clippy with warnings as errors
	$(CARGO) clippy --all-targets -- -D warnings

fmt: ## Format sources
	$(CARGO) fmt

clean: ## Remove build artifacts
	$(CARGO) clean
