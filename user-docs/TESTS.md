# Testing

The active gateway and control plane test suite is entirely Rust-based.

## Prerequisites

- Rust 1.88 with `rustfmt` and `clippy`
- Node.js 22 for the dashboard build
- Docker for image and Compose validation

## Local checks

### One-command automated E2E run

```bash
make local-e2e
```

`make test-e2e` remains an alias for `make local-e2e`.
No separately running Doorman server is needed. This sequential, fail-fast runner:

1. Tests the Python verification scripts and checks the pinned reference plus the
   test and production-source coverage ledgers.
2. Runs Rust formatting, Clippy, and the full Cargo suite (including protocol,
   platform, persistence, and process-lifecycle tests).
3. Installs frontend dependencies and builds the dashboard.
4. Starts isolated MongoDB/Redis with Compose and explicitly enables the external
   storage tests. An ordinary `make test` does **not** exercise those dependencies.
5. Builds the candidate Docker image, starts it with fresh test credentials and
   disposable in-memory data, checks backend readiness and frontend HTTP, and
   runs the normally ignored live TCP/auth test against that image.
6. Removes its temporary container and Compose resources, keeping logs and reports.

Requires Python 3, Git, Make, Bash, Cargo/rustfmt/Clippy, npm, and a working Docker
daemon with Compose v2. The runner finds Rust in `~/.cargo/bin` automatically.
Dependency downloads/image pulls require network access. Do **not** use `sudo make`.
The external-storage fixture selects invocation-specific loopback ports; override
them with `DOORMAN_TEST_MONGO_PORT` / `DOORMAN_TEST_REDIS_PORT` when needed.
The disposable candidate also uses automatically assigned loopback ports and never
mounts your data or reads your root `.env`. Existing Doorman services are untouched.
Run only one E2E invocation per checkout at a time: Cargo/frontend build directories
are shared. The runner stays sequential under `make -j`.

Each run creates a private, unique `release-evidence/<UTC>-<suffix>/` directory
containing per-stage logs, source revision/status, immutable local image ID, and
`summary.json`. Failed and interrupted runs keep their evidence; they cannot report
success. Evidence is gitignored and excluded from Docker builds. Set
`E2E_EVIDENCE_ROOT` to change its parent directory. Built images and dependency/build
caches are retained; the runner never prunes Docker or deletes existing project data.

Preview all gates or check tool availability without building:

```bash
make e2e-plan
python3 scripts/run_e2e.py --preflight
```

### Full release gate

```bash
make release-e2e
```

This runs everything above **plus** an owned recovery rehearsal, live
Python/Rust differential comparison, four-protocol performance comparison, and
`release-check`. Missing release prerequisites fail **before** expensive builds.
There are no skip flags. A passing `local-e2e` is not a release sign-off.

The runner automatically builds the exact pinned Python reference, starts
deterministic REST, GraphQL, SOAP, and gRPC upstreams, seeds independent Python
and Rust fixtures, and creates the benchmark scenario file. It also uses a private
Docker volume to prove Python snapshot restore, Python-to-Rust cutover, and
Rust-to-Python rollback with fresh authentication and all four protocols. Before
cutover it changes the disposable data volume to the Rust image's `10001:10001`
runtime ownership.

Release configuration is still explicit:

- Export the production-like configuration variables listed under "Release evidence
  check" below. Use an isolated rehearsal environment, never a production target.
- Docker must be able to pull the Python 3.12 and Node 22 base images and build the
  pinned reference dependencies. On Linux, the harness uses random host ports bound
  to loopback so the benchmark can inspect the actual server PIDs. It creates only
  random, invocation-owned container and volume names. It removes those resources
  on success, failure, or interruption and retains container/build logs in the
  evidence directory.

The runner generates fresh report paths itself; caller-supplied old report paths
are not reused. Benchmark trials must have zero failed requests on both servers,
in addition to the existing relative no-regression thresholds. Preflight can be
run independently with `python3 scripts/run_e2e.py --release --preflight`.

The automated recovery rehearsal uses encrypted memory snapshots because v2 is a
fresh deployment and live v1 data migration is outside the launch scope. The separate
external-storage stage proves MongoDB/Redis behavior. Frontend HTTP and build checks
are not browser workflow tests, and this runner does not add new soak tests. The
differential stage now generates one authenticated synthetic boundary probe for all
178 pinned OpenAPI operations in addition to the deeper curated scenarios. It does
not provide a successful state-transition fixture for every operation; keep that
remaining coverage work explicit.

From the repository root:

```bash
make check
make web-build
```

The equivalent direct commands are:

```bash
cargo fmt --manifest-path gateway-rs/Cargo.toml --all -- --check
cargo clippy --manifest-path gateway-rs/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo test --manifest-path gateway-rs/Cargo.toml --locked
npm --prefix web-client ci
npm --prefix web-client run build
```

Rust integration tests use in-process upstream servers and do not require MongoDB or Redis. Storage and platform tests use the native in-memory backend. Checked-in parity fixtures preserve the pre-Rust public wire contract.

## Live smoke test

Start Doorman:

```bash
cp .env.demo .env
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build
```

In another terminal:

```bash
make smoke
```

## Shared-storage verification

Use the external profile when testing MongoDB/Redis behavior:

```bash
MEM_OR_EXTERNAL=REDIS docker compose --profile external up --build
make smoke
```

## Local system suite

The system harness owns every container, network, volume, port, credential, and
artifact it creates. It does not read the repository `.env`, attach to an existing
container, use a fixed host port, or run a Docker prune. Start with the offline
contract checks and deterministic execution plan:

```bash
make system-e2e-check
make system-e2e-plan
```

Runtime profiles build the exact working tree once, identify it by immutable image
ID, start ten independent protocol fixtures, and retain a private evidence directory
under `system-e2e-evidence/`:

```bash
make system-e2e-smoke       # five-minute budget, memory topology
make system-e2e             # 30-minute budget, complete topology contract
make system-e2e-soak        # 60-minute two-node workload contract
```

These commands are fail-closed. A missing executor, skipped scenario, product
mismatch, uncovered pair, stale approval, infrastructure failure, or budget overrun
returns nonzero and is recorded in `system-e2e-report.json`. Harness completeness
(`make system-e2e-check`) only proves that the manifests and generated ledger are
self-consistent; it is not evidence that the product passed the runtime suite.

Each report records its 24-hex-character `run_id`. Cleanup normally runs on success,
failure, SIGTERM, and Ctrl-C. To recover resources from a killed runner, supply that
exact ID; only Docker resources with the matching ownership label are removed:

```bash
SYSTEM_E2E_RUN_ID=<run-id> make system-e2e-clean
```

The evidence directory contains the machine-readable report, per-container logs,
resolved fixture addresses, baseline protocol probes, and `replay.json`. The replay
file records the deterministic seed and command but no credentials. Fixture and
candidate credentials are random per run, are passed through a private mounted file,
are never printed, and the file is deleted during cleanup.

The reviewed inputs are in `system-tests/`: `contract.json` defines operation
classes, settings, UI inventory digest, and higher-order packs; `pairwise.json`
defines constrained feature axes; `upstreams.json` defines the ten profiles;
`approvals.json` contains exact, owned, expiring differences; and
`report.schema.json` defines authoritative evidence. UI and frozen OpenAPI inventories
are discovered from source, so additions fail the checker until reviewed.

## Release evidence check

A release candidate must include a fresh zero-difference differential report, a
passing Python-versus-Rust performance report, and the log from the isolated
MongoDB/Redis suite. The final check is intentionally fail-closed:

```bash
EXTERNAL_STORAGE_LOG=release-evidence/external-storage.log \
  bash scripts/run_external_storage_tests.sh

ENV=production MEM_OR_EXTERNAL=REDIS \
HTTPS_ONLY=true CORS_STRICT=true LOCAL_HOST_IP_BYPASS=false \
DOORMAN_ADMIN_EMAIL=admin@example.com \
DOORMAN_ADMIN_PASSWORD='use-a-real-secret' \
JWT_SECRET_KEY='use-a-unique-signing-key' \
JWT_ISSUER=doorman-production JWT_AUDIENCE=doorman-clients \
ALLOWED_ORIGINS=https://admin.example.com \
DISCOVERY_ALLOWED_HOSTS=api.example.com \
MONGO_DB_HOSTS=mongo.example.com:27017 \
MONGO_DB_USER=doorman-release MONGO_DB_PASSWORD='use-a-real-mongo-secret' \
REDIS_HOST=redis.example.com REDIS_PASSWORD='use-a-real-redis-secret' \
PARITY_REPORT=release-evidence/differential.json \
PARITY_PERF_REPORT=release-evidence/performance.json \
EXTERNAL_STORAGE_LOG=release-evidence/external-storage.log \
RELEASE_OPERATIONS_REPORT=release-evidence/operations.json \
SYSTEM_E2E_REPORT=system-e2e-evidence/<run-id>/system-e2e-report.json \
make release-check
```

Evidence defaults to a maximum age of 24 hours; set
`DOORMAN_RELEASE_EVIDENCE_MAX_AGE_HOURS` only when the release policy explicitly
allows a longer review window. Scheduled CI runs the external-storage suite and
retains its Compose logs for 14 days, including on failures.

The differential report is accepted only when it records the SHA-256 of the
checked-in scenario manifest, pinned OpenAPI artifact, and operation approval
manifest. It must contain one result for each curated scenario plus the OpenAPI
comparison, and exactly one authenticated synthetic boundary result for each of the
178 pinned method/path pairs. The operation result compares exact status, response
media type, and `Allow` methods. Missing, duplicate, stale-approved, or unapproved
operation differences fail the release check. This prevents a partial or empty
zero-difference report from being used as release evidence.

`operations.json` is the signed-off record produced from the release runbook.
It must be a schema-version-1 JSON object with each of these fields set to
`{"passed": true}`: `image_smoke`, `restore_rehearsal`, `cutover`, and
`rollback`. The checker rejects an incomplete or failed rehearsal record.

`SYSTEM_E2E_REPORT` must be a fresh, passing comprehensive report from the current
system-test manifests. The release checker requires all 178 operations, every valid
generated pair, all dashboard workflows, all three topologies, zero skipped tests,
zero failures, and the immutable candidate image ID.

The performance report must come from `make parity-performance` using four
representative, policy-enabled candidate routes. Set `PARITY_PERF_SCENARIOS` to
a private JSON file containing named `rest`, `graphql`, `soap`, and `grpc`
entries. Each entry has `python_url`, `rust_url`, and an optional `request`
object (`method`, string-map `headers`, and string `body`), so POST-based
GraphQL, SOAP, and gRPC requests are measured faithfully. The benchmark never
writes request headers or bodies to its report. The release checker rejects a
health-only or incomplete performance report.

## Container checks

```bash
docker compose config
docker build -t doorman:local .
```
