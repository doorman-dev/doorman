#!/usr/bin/env python3
"""Validate the evidence and production configuration required for a release.

This deliberately does not build or deploy anything.  It is the final, fail-closed
evidence check to run after the release commands have generated their reports.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from differential_parity import OPERATION_PROBE_PROFILE, load_openapi, operation_cases


REQUIRED_ENVIRONMENT = {
    "ENV": {"production"},
    "MEM_OR_EXTERNAL": {"redis", "external"},
    "HTTPS_ONLY": {"true"},
    "CORS_STRICT": {"true"},
    "LOCAL_HOST_IP_BYPASS": {"false"},
}
REQUIRED_VALUES = (
    "DOORMAN_ADMIN_EMAIL",
    "DOORMAN_ADMIN_PASSWORD",
    "JWT_SECRET_KEY",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "ALLOWED_ORIGINS",
    "DISCOVERY_ALLOWED_HOSTS",
    "MONGO_DB_HOSTS",
    "MONGO_DB_USER",
    "MONGO_DB_PASSWORD",
    "REDIS_HOST",
    "REDIS_PASSWORD",
    "PARITY_REPORT",
    "PARITY_PERF_REPORT",
    "EXTERNAL_STORAGE_LOG",
    "RELEASE_OPERATIONS_REPORT",
    "SYSTEM_E2E_REPORT",
)
PLACEHOLDERS = {"", "please-change-me", "changeme", "change-me", "example", "todo"}
REQUIRED_PERFORMANCE_PROFILES = ("rest", "graphql", "soap", "grpc")
PERFORMANCE_METRICS = (
    "throughput_rps",
    "p95_latency_ms",
    "error_rate",
    "peak_rss_bytes",
)


def fail(message: str) -> None:
    raise ValueError(message)


def required_environment() -> None:
    for name, allowed in REQUIRED_ENVIRONMENT.items():
        value = os.environ.get(name, "").strip().lower()
        if value not in allowed:
            fail(f"{name} must be one of {', '.join(sorted(allowed))}")
    for name in REQUIRED_VALUES:
        value = os.environ.get(name, "").strip()
        if value.lower() in PLACEHOLDERS:
            fail(f"{name} must be set to a non-placeholder value")
    for name in ("DOORMAN_ADMIN_PASSWORD", "JWT_SECRET_KEY", "MONGO_DB_PASSWORD", "REDIS_PASSWORD"):
        if len(os.environ[name].strip()) < 16:
            fail(f"{name} must be at least 16 characters")


def report_path(name: str) -> Path:
    path = Path(os.environ[name]).expanduser()
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"{name} must point to a non-empty report file: {path}")
    max_age = float(os.environ.get("DOORMAN_RELEASE_EVIDENCE_MAX_AGE_HOURS", "24"))
    if not math.isfinite(max_age) or max_age <= 0:
        fail("DOORMAN_RELEASE_EVIDENCE_MAX_AGE_HOURS must be greater than zero")
    age_seconds = time.time() - path.stat().st_mtime
    if age_seconds < -300:
        fail(f"{name} is dated more than five minutes in the future: {path}")
    if age_seconds > max_age * 3600:
        fail(f"{name} is older than the allowed evidence age ({max_age:g} hours): {path}")
    return path


def load_report(name: str) -> dict[str, Any]:
    path = report_path(name)
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{name} is not valid JSON: {error}")
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        fail(f"{name} must be a schema_version 1 JSON report")
    return value


def validate_reports() -> None:
    differential = load_report("PARITY_REPORT")
    if not isinstance(differential.get("results"), list):
        fail("PARITY_REPORT must contain a curated results list")
    scenario_path = Path(__file__).resolve().parents[1] / "parity/differential/scenarios.json"
    expected_hash = hashlib.sha256(scenario_path.read_bytes()).hexdigest()
    if differential.get("scenario_manifest_sha256") != expected_hash:
        fail("PARITY_REPORT must be generated from the checked-in differential scenario manifest")
    expected_scenarios = {
        case["name"] for case in json.loads(scenario_path.read_text())
    } | {"openapi"}
    actual_scenarios = {
        result.get("name") for result in differential["results"] if isinstance(result, dict)
    }
    if actual_scenarios != expected_scenarios:
        fail("PARITY_REPORT must contain one result for every differential scenario")

    repo_root = Path(__file__).resolve().parents[1]
    openapi_path = repo_root / "parity/openapi/python-openapi.json.gz.b64"
    openapi_bytes, openapi_document = load_openapi(openapi_path)
    if differential.get("openapi_artifact_sha256") != hashlib.sha256(openapi_bytes).hexdigest():
        fail("PARITY_REPORT must be generated from the checked-in OpenAPI artifact")
    approvals_path = repo_root / "parity/differential/operation_approvals.json"
    approval_bytes = approvals_path.read_bytes()
    try:
        approvals = json.loads(approval_bytes)
    except json.JSONDecodeError as error:
        fail(f"operation approval manifest is not valid JSON: {error}")
    if not isinstance(approvals, dict):
        fail("operation approval manifest must be an object")
    if differential.get("operation_approvals_sha256") != hashlib.sha256(approval_bytes).hexdigest():
        fail("PARITY_REPORT must use the checked-in operation approval manifest")
    if differential.get("probe_profile") != OPERATION_PROBE_PROFILE:
        fail("PARITY_REPORT must use the authenticated operation probe profile")
    matrix = differential.get("operation_matrix")
    matrix_results = matrix.get("results") if isinstance(matrix, dict) else None
    expected_operations = {case["name"]: case for case in operation_cases(openapi_document)}
    expected_count = json.loads((repo_root / "parity/reference.json").read_text())["surface"][
        "openapi_operations"
    ]
    if expected_count != len(expected_operations):
        fail("checked-in OpenAPI operation count does not match parity/reference.json")
    if not isinstance(matrix_results, list) or matrix.get("operation_count") != expected_count:
        fail("PARITY_REPORT operation matrix must cover every pinned operation")
    if matrix.get("differences") != 0:
        fail(
            "PARITY_REPORT operation matrix contains "
            f"{matrix.get('differences')} unapproved differences"
        )
    actual_operations = [
        result.get("name") for result in matrix_results if isinstance(result, dict)
    ]
    if len(actual_operations) != expected_count or set(actual_operations) != set(expected_operations):
        fail("PARITY_REPORT operation matrix must contain each pinned operation exactly once")
    for result in matrix_results:
        expected = expected_operations[result["name"]]
        if (
            result.get("method") != expected["method"]
            or result.get("path_template") != expected["path_template"]
            or result.get("operation_id") != expected["operation_id"]
            or result.get("probe_depth") != "authenticated_synthetic_boundary"
            or not isinstance(result.get("match"), bool)
        ):
            fail(f"PARITY_REPORT has invalid operation evidence for {result['name']}")
        expected_approval = approvals.get(result["name"])
        if result.get("approved_divergence") != expected_approval:
            fail(f"PARITY_REPORT has unreviewed approval metadata for {result['name']}")
        if result["match"] and expected_approval:
            fail(f"operation approval is stale because the probe now matches: {result['name']}")
        if not result["match"] and not expected_approval:
            fail(f"PARITY_REPORT contains an unapproved operation difference: {result['name']}")
    if differential.get("differences") != 0:
        fail(
            "PARITY_REPORT contains "
            f"{differential.get('differences')} total unapproved differences"
        )

    performance = load_report("PARITY_PERF_REPORT")
    profiles = performance.get("profiles")
    if performance.get("failures") != [] or not isinstance(profiles, dict):
        fail("PARITY_PERF_REPORT must contain an empty failures list and profiles")
    for field in ("trials", "requests_per_trial", "concurrency"):
        value = performance.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail(f"PARITY_PERF_REPORT must contain a positive integer {field}")
    missing_profiles = [name for name in REQUIRED_PERFORMANCE_PROFILES if name not in profiles]
    if missing_profiles:
        fail(
            "PARITY_PERF_REPORT must cover REST, GraphQL, SOAP, and gRPC; "
            f"missing: {', '.join(missing_profiles)}"
        )
    for profile_name in REQUIRED_PERFORMANCE_PROFILES:
        profile = profiles[profile_name]
        summary = profile.get("summary") if isinstance(profile, dict) else None
        if not isinstance(summary, dict):
            fail(f"PARITY_PERF_REPORT profile {profile_name} must contain a summary")
        for implementation in ("python", "rust"):
            metrics = summary.get(implementation)
            if not isinstance(metrics, dict):
                fail(
                    "PARITY_PERF_REPORT profile "
                    f"{profile_name} must contain {implementation} metrics"
                )
            for metric in PERFORMANCE_METRICS:
                value = metrics.get(metric)
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    or value < 0
                ):
                    fail(
                        "PARITY_PERF_REPORT profile "
                        f"{profile_name} must contain non-negative {implementation} metrics"
                    )
            if metrics["throughput_rps"] <= 0 or metrics["peak_rss_bytes"] <= 0:
                fail(
                    "PARITY_PERF_REPORT profile "
                    f"{profile_name} must contain nonzero {implementation} throughput and RSS"
                )
            if metrics["error_rate"] > 1:
                fail(
                    "PARITY_PERF_REPORT profile "
                    f"{profile_name} must contain an {implementation} error rate from zero to one"
                )

    external_log = report_path("EXTERNAL_STORAGE_LOG")
    try:
        external_output = external_log.read_text(errors="replace")
    except OSError as error:
        fail(f"EXTERNAL_STORAGE_LOG cannot be read: {error}")
    if "test result: ok." not in external_output or "test result: FAILED" in external_output:
        fail(
            "EXTERNAL_STORAGE_LOG must contain a successful Cargo test summary; "
            "generate it with EXTERNAL_STORAGE_LOG=<path> "
            "bash scripts/run_external_storage_tests.sh"
        )

    release_image_id = os.environ.get("RELEASE_IMAGE_ID", "").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", release_image_id):
        fail("RELEASE_IMAGE_ID must identify the immutable candidate image")

    operations = load_report("RELEASE_OPERATIONS_REPORT")
    if operations.get("image_id") != release_image_id:
        fail("RELEASE_OPERATIONS_REPORT was not generated for RELEASE_IMAGE_ID")
    required_operations = ("image_smoke", "restore_rehearsal", "cutover", "rollback")
    for operation in required_operations:
        evidence = operations.get(operation)
        if not isinstance(evidence, dict) or evidence.get("passed") is not True:
            fail(
                "RELEASE_OPERATIONS_REPORT must record a passing "
                f"{operation} rehearsal"
            )

    system = load_report("SYSTEM_E2E_REPORT")
    if system.get("profile") != "comprehensive" or system.get("status") != "passed":
        fail("SYSTEM_E2E_REPORT must be a passing comprehensive report")
    topologies = system.get("topologies")
    expected_topologies = ["memory", "external", "two-node"]
    if (
        not isinstance(topologies, list)
        or not all(isinstance(item, dict) for item in topologies)
        or [item.get("name") for item in topologies] != expected_topologies
        or any(item.get("status") != "passed" for item in topologies)
    ):
        fail("SYSTEM_E2E_REPORT must contain memory, external, and two-node evidence")
    counts = system.get("scenario_counts")
    if (
        not isinstance(counts, dict)
        or counts.get("planned") != counts.get("passed")
        or counts.get("failed") != 0
        or counts.get("skipped") != 0
    ):
        fail("SYSTEM_E2E_REPORT must pass every planned scenario without skips")
    operation_coverage = system.get("operation_coverage")
    if (
        not isinstance(operation_coverage, dict)
        or operation_coverage.get("total") != 178
        or operation_coverage.get("covered") != operation_coverage.get("total")
    ):
        fail("SYSTEM_E2E_REPORT must cover all 178 frozen operations")
    for name in ("pair_coverage", "ui_coverage"):
        coverage = system.get(name)
        total_key = "valid" if name == "pair_coverage" else "total"
        if not isinstance(coverage, dict) or coverage.get("covered") != coverage.get(total_key):
            fail(f"SYSTEM_E2E_REPORT has incomplete {name}")
    if system.get("failures") != [] or system.get("infrastructure_errors") != []:
        fail("SYSTEM_E2E_REPORT contains failures or infrastructure errors")
    image_id = system.get("candidate_image_id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        fail("SYSTEM_E2E_REPORT must identify the immutable candidate image")
    if image_id != release_image_id:
        fail("SYSTEM_E2E_REPORT was not generated for RELEASE_IMAGE_ID")
    expected_manifests = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (
            repo_root / "system-tests/contract.json",
            repo_root / "system-tests/pairwise.json",
            repo_root / "system-tests/upstreams.json",
        )
    }
    if system.get("manifest_hashes") != expected_manifests:
        fail("SYSTEM_E2E_REPORT was not generated from the current system-test manifests")


def run_generated_checks(repo_root: Path) -> None:
    for command in (
        [sys.executable, "scripts/check_parity_reference.py"],
        [sys.executable, "scripts/generate_test_coverage_ledger.py", "--check"],
        [sys.executable, "scripts/generate_source_coverage_ledger.py", "--check"],
    ):
        completed = subprocess.run(command, cwd=repo_root, check=False)
        if completed.returncode != 0:
            fail(f"generated parity check failed: {' '.join(command)}")


def main() -> int:
    try:
        required_environment()
        validate_reports()
        run_generated_checks(Path(__file__).resolve().parents[1])
    except ValueError as error:
        print(f"release evidence check failed: {error}", file=sys.stderr)
        return 1
    print("release evidence check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
