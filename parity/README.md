# Gateway Contract Fixtures

This directory holds the frozen public wire contracts captured before the Rust
cutover. The Rust integration suite uses them to detect accidental compatibility
regressions.

## Contract Fixtures

- `contracts/schema.json` documents the fixture format.
- `contracts/fixtures/*.json` are checked-in goldens for canonical
  `/api/*` behavior.
- `schemas/decision-trace.schema.json` documents retained decision traces.

Run the Rust contract comparisons with the rest of the gateway suite:

```bash
make test
```

The Python oracle is pinned in `reference.json`. Verify the commit, dependency
hash, OpenAPI inventory, test-file inventory, and fixture coverage with:

```bash
make parity-reference
```

## Python-to-Rust test coverage ledger

`test_coverage_ledger.json` is the generated, pinned inventory of every Python
test case in the frozen reference. `test_coverage_overrides.json` is the small,
reviewed source of truth for its disposition and exact Rust assertion mapping.
The format is documented by `test_coverage_ledger.schema.json`.

Each case is one of `covered`, `approved_changed`, `approved_obsolete`, or
`missing`. A case can be marked `covered` only with one or more Rust test IDs
whose assertions cover the Python case; a similarly named or broader test is
not sufficient. Approved changes and obsoletions require a rationale. Unlisted
cases intentionally generate as `missing`, so progress cannot be inferred.

After reviewing a case, update the override file and regenerate the ledger:

```bash
python3 scripts/generate_test_coverage_ledger.py --write
make parity-ledger
```

`make parity` and Rust CI verify that the checked-in ledger exactly matches the
pinned commit. The verification report includes counts by suite/domain and
status, allowing incremental migration work to target a concrete gap.

## Python-to-Rust source coverage ledger

`source_coverage_ledger.json` inventories production Python modules, classes,
fields, functions, and methods from the same pinned reference. It exists because
test disposition alone cannot prove that untested Python behavior was translated.
`source_coverage_overrides.json` records the reviewed Rust symbol and test evidence
for each unit. Large uniform modules may use a file default, with exact symbol
entries taking precedence for partial or obsolete exceptions.

Unlisted units generate as `unreviewed`. A unit is `translated` only when the
override identifies both its Rust implementation and assertion-level tests.
`partial` and `missing` keep incomplete work visible; approved changes and
obsoletions require explicit rationales.

```bash
python3 scripts/generate_source_coverage_ledger.py --write
make parity-source-ledger
```

The source-unit percentage measures inventory review, not semantic weighting or
release readiness. Complete parity also requires the operation and system evidence
described below.

With the pinned Python server on port 3102 and Rust on port 3101, provide a fresh
administrator token for each disposable fixture and run the differential comparison:

```bash
PYTHON_PARITY_TOKEN='<python-token>' \
RUST_PARITY_TOKEN='<rust-token>' \
make parity-differential
```

The differential runner exits non-zero for any unclassified difference and can
write a machine-readable report through `PARITY_REPORT`. The release fixture
harness creates these tokens automatically and passes them only through the child
environment.

The report contains two evidence levels. The curated scenarios compare complete
normalized responses for representative public, authentication, CORS, and OpenAPI
behavior. The generated operation matrix reads the pinned OpenAPI artifact and sends
one authenticated synthetic boundary request for each of its 178 method/path pairs.
It compares exact status, response media type, and `Allow` methods. These probes use
required path/query values and intentionally omit request bodies, so they cover route,
authorization, validation, and missing-resource behavior; they do not claim a
successful state transition for every operation. The four-protocol release fixtures
provide deeper successful REST, GraphQL, SOAP, and gRPC coverage.

Reviewed operation-level differences belong in
`differential/operation_approvals.json` with a concrete rationale. Unknown and stale
approvals fail, and the release evidence checker verifies hashes for the OpenAPI
artifact and approval manifest plus exactly one result for every pinned operation.

Contract comparison normalizes only volatile fields such as request IDs and
timestamps. Meaningful wire headers, including compression, gRPC status/encoding,
cookies, and rate-limit headers, remain part of the contract.
