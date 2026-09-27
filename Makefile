SHELL := /bin/bash

PORT ?= $(shell grep '^PORT=' .env 2>/dev/null | cut -d'=' -f2 || echo 3001)
ADMIN_EMAIL ?= $(shell grep '^DOORMAN_ADMIN_EMAIL=' .env 2>/dev/null | cut -d'=' -f2)
ADMIN_PASSWORD ?= $(shell grep '^DOORMAN_ADMIN_PASSWORD=' .env 2>/dev/null | cut -d'=' -f2)
BASE_URL ?= http://localhost:$(PORT)
GATEWAY_LOAD_BASE_URL ?= http://localhost:3001

.PHONY: check test unit unitq rust-test rust-clippy rust-fmt-check web-audit web-build parity parity-reference parity-ledger parity-source-ledger parity-contracts parity-differential parity-performance release-check local-e2e test-e2e release-e2e e2e-plan system-e2e-smoke system-e2e system-e2e-soak system-e2e-plan system-e2e-check system-e2e-clean test-live-tcp smoke preflight live liveq gateway-load external-storage-test clean clean-deep

check: rust-fmt-check rust-clippy test

parity: parity-reference parity-ledger parity-source-ledger parity-contracts

parity-reference:
	python3 scripts/check_parity_reference.py

parity-ledger:
	python3 scripts/generate_test_coverage_ledger.py --check

parity-source-ledger:
	python3 scripts/generate_source_coverage_ledger.py --check

parity-contracts:
	cargo test --manifest-path gateway-rs/Cargo.toml --locked --test parity_contracts --test openapi_parity --test auth_rate_parity

parity-differential:
	python3 scripts/differential_parity.py \
		--python-url "$${PYTHON_PARITY_URL:-http://127.0.0.1:3102}" \
		--rust-url "$${RUST_PARITY_URL:-http://127.0.0.1:3101}" \
		--report "$${PARITY_REPORT:-parity-report.json}"

parity-performance:
	python3 scripts/benchmark_parity.py \
		--python-pid "$${PYTHON_PARITY_PID:?set PYTHON_PARITY_PID}" \
		--rust-pid "$${RUST_PARITY_PID:?set RUST_PARITY_PID}" \
		--scenarios "$${PARITY_PERF_SCENARIOS:?set PARITY_PERF_SCENARIOS}" \
		--report "$${PARITY_PERF_REPORT:-parity-performance.json}"

release-check:
	python3 scripts/release_check.py

# One sequential runner, even under make -j. It owns its disposable server.
local-e2e:
	python3 scripts/run_e2e.py

# Backward-compatible alias; requesting both targets runs the suite only once.
test-e2e: local-e2e

release-e2e:
	python3 scripts/run_e2e.py --release

e2e-plan:
	python3 scripts/run_e2e.py --release --plan

system-e2e-smoke:
	python3 scripts/system_e2e.py --profile smoke

system-e2e:
	python3 scripts/system_e2e.py --profile comprehensive

system-e2e-soak:
	python3 scripts/system_e2e.py --profile soak

system-e2e-plan:
	python3 scripts/system_e2e.py --profile comprehensive --plan

system-e2e-check:
	python3 scripts/system_e2e.py --check

system-e2e-clean:
	python3 scripts/system_e2e.py --clean "$${SYSTEM_E2E_RUN_ID:?set SYSTEM_E2E_RUN_ID to the exact run ID}"

test unit unitq rust-test:
	cargo test --manifest-path gateway-rs/Cargo.toml --locked

rust-clippy:
	cargo clippy --manifest-path gateway-rs/Cargo.toml --locked --all-targets --all-features -- -D warnings

rust-fmt-check:
	cargo fmt --manifest-path gateway-rs/Cargo.toml --all -- --check

web-build:
	npm --prefix web-client ci
	npm --prefix web-client run build

web-audit:
	npm --prefix web-client audit --omit=dev --audit-level=high

smoke preflight live liveq:
	BASE_URL=$(BASE_URL) \
	DOORMAN_ADMIN_EMAIL=$(ADMIN_EMAIL) \
	DOORMAN_ADMIN_PASSWORD=$(ADMIN_PASSWORD) \
	bash scripts/preflight.sh

test-live-tcp:
	PATH="$(HOME)/.cargo/bin:$(PATH)" \
	LIVE_SERVER_URL=$(BASE_URL) \
	DOORMAN_ADMIN_EMAIL=$(ADMIN_EMAIL) \
	DOORMAN_ADMIN_PASSWORD=$(ADMIN_PASSWORD) \
	cargo test --test live_tcp_port_3001 --manifest-path gateway-rs/Cargo.toml -- --ignored --nocapture

gateway-load:
	BASE_URL=$(GATEWAY_LOAD_BASE_URL) bash scripts/run_perf_check.sh

clean:
	@echo "Cleaning Rust, web, and runtime artifacts..."
	@rm -rf gateway-rs/target web-client/.next
	@rm -f doorman.pid
	@echo "Done."
external-storage-test:
	bash scripts/run_external_storage_tests.sh


clean-deep: clean
	@echo "Removing generated runtime data..."
	@rm -rf data logs
	@echo "Done."
