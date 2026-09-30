#!/usr/bin/env python3
"""Focused regression tests for the fail-closed release evidence checker."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.differential_parity import OPERATION_PROBE_PROFILE, load_openapi, operation_cases


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK = REPO_ROOT / "scripts" / "release_check.py"


class ReleaseCheckTests(unittest.TestCase):
    def base_environment(self, evidence: Path) -> dict[str, str]:
        differential = evidence / "differential.json"
        scenario_path = REPO_ROOT / "parity" / "differential" / "scenarios.json"
        scenario_names = [case["name"] for case in json.loads(scenario_path.read_text())]
        openapi_path = REPO_ROOT / "parity" / "openapi" / "python-openapi.json.gz.b64"
        openapi_bytes, openapi_document = load_openapi(openapi_path)
        approvals_path = REPO_ROOT / "parity" / "differential" / "operation_approvals.json"
        approvals = json.loads(approvals_path.read_text())
        operation_results = [
            {
                "name": case["name"],
                "method": case["method"],
                "path_template": case["path_template"],
                "operation_id": case["operation_id"],
                "probe_depth": "authenticated_synthetic_boundary",
                "match": case["name"] not in approvals,
                "approved_divergence": approvals.get(case["name"]),
            }
            for case in operation_cases(openapi_document)
        ]
        differential.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "scenario_manifest_sha256": hashlib.sha256(scenario_path.read_bytes()).hexdigest(),
                    "openapi_artifact_sha256": hashlib.sha256(openapi_bytes).hexdigest(),
                    "operation_approvals_sha256": hashlib.sha256(
                        approvals_path.read_bytes()
                    ).hexdigest(),
                    "probe_profile": OPERATION_PROBE_PROFILE,
                    "differences": 0,
                    "results": [{"name": name} for name in [*scenario_names, "openapi"]],
                    "operation_matrix": {
                        "operation_count": len(operation_results),
                        "differences": 0,
                        "results": operation_results,
                    },
                }
            )
        )
        performance = evidence / "performance.json"
        performance.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "failures": [],
                    "trials": 1,
                    "requests_per_trial": 1,
                    "concurrency": 1,
                    "profiles": {
                        profile: {
                            "summary": {
                                "python": {
                                    "throughput_rps": 1,
                                    "p95_latency_ms": 1,
                                    "error_rate": 0,
                                    "peak_rss_bytes": 1,
                                },
                                "rust": {
                                    "throughput_rps": 1,
                                    "p95_latency_ms": 1,
                                    "error_rate": 0,
                                    "peak_rss_bytes": 1,
                                },
                            }
                        }
                        for profile in ("rest", "graphql", "soap", "grpc")
                    },
                }
            )
        )
        external_log = evidence / "external.log"
        external_log.write_text("test result: ok. 7 passed; 0 failed; 0 ignored\n")
        operations = evidence / "operations.json"
        operations.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "image_id": "sha256:" + "a" * 64,
                    "image_smoke": {"passed": True},
                    "restore_rehearsal": {"passed": True},
                    "cutover": {"passed": True},
                    "rollback": {"passed": True},
                }
            )
        )
        system_e2e = evidence / "system-e2e-report.json"
        system_e2e.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "passed",
                    "profile": "comprehensive",
                    "candidate_image_id": "sha256:" + "a" * 64,
                    "topologies": [
                        {"name": "memory", "status": "passed"},
                        {"name": "external", "status": "passed"},
                        {"name": "two-node", "status": "passed"},
                    ],
                    "scenario_counts": {"planned": 10, "passed": 10, "failed": 0, "skipped": 0},
                    "operation_coverage": {"total": 178, "covered": 178},
                    "pair_coverage": {"valid": 10, "covered": 10},
                    "ui_coverage": {"total": 10, "covered": 10},
                    "failures": [],
                    "infrastructure_errors": [],
                    "manifest_hashes": {
                        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in (
                            REPO_ROOT / "system-tests/contract.json",
                            REPO_ROOT / "system-tests/pairwise.json",
                            REPO_ROOT / "system-tests/upstreams.json",
                        )
                    },
                }
            )
        )
        return {
            **os.environ,
            "ENV": "production",
            "MEM_OR_EXTERNAL": "REDIS",
            "HTTPS_ONLY": "true",
            "CORS_STRICT": "true",
            "LOCAL_HOST_IP_BYPASS": "false",
            "DOORMAN_ADMIN_EMAIL": "admin@example.test",
            "DOORMAN_ADMIN_PASSWORD": "not-a-placeholder-password",
            "JWT_SECRET_KEY": "a-unique-long-secret-key",
            "JWT_ISSUER": "doorman-release",
            "JWT_AUDIENCE": "doorman-clients",
            "ALLOWED_ORIGINS": "https://admin.example.test",
            "DISCOVERY_ALLOWED_HOSTS": "api.example.test",
            "MONGO_DB_HOSTS": "mongo.example.test:27017",
            "MONGO_DB_USER": "doorman-release-user",
            "MONGO_DB_PASSWORD": "mongo-release-password",
            "REDIS_HOST": "redis.example.test",
            "REDIS_PASSWORD": "redis-release-password",
            "PARITY_REPORT": str(differential),
            "PARITY_PERF_REPORT": str(performance),
            "EXTERNAL_STORAGE_LOG": str(external_log),
            "RELEASE_OPERATIONS_REPORT": str(operations),
            "SYSTEM_E2E_REPORT": str(system_e2e),
            "RELEASE_IMAGE_ID": "sha256:" + "a" * 64,
        }

    def run_check(self, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECK)],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_current_evidence_and_rejects_missing_or_failed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.base_environment(Path(directory))
            self.assertEqual(self.run_check(environment).returncode, 0)

            environment.pop("JWT_SECRET_KEY")
            self.assertNotEqual(self.run_check(environment).returncode, 0)
            environment = self.base_environment(Path(directory))
            Path(environment["PARITY_REPORT"]).write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenario_manifest_sha256": hashlib.sha256(
                            (REPO_ROOT / "parity" / "differential" / "scenarios.json").read_bytes()
                        ).hexdigest(),
                        "differences": 1,
                        "results": [],
                    }
                )
            )
            self.assertNotEqual(self.run_check(environment).returncode, 0)

            environment = self.base_environment(Path(directory))
            Path(environment["RELEASE_OPERATIONS_REPORT"]).write_text(
                json.dumps({"schema_version": 1, "image_smoke": {"passed": True}})
            )
            self.assertNotEqual(self.run_check(environment).returncode, 0)

            environment = self.base_environment(Path(directory))
            performance = json.loads(Path(environment["PARITY_PERF_REPORT"]).read_text())
            del performance["profiles"]["grpc"]
            Path(environment["PARITY_PERF_REPORT"]).write_text(json.dumps(performance))
            self.assertNotEqual(self.run_check(environment).returncode, 0)

            environment = self.base_environment(Path(directory))
            environment["HTTPS_ONLY"] = "false"
            self.assertNotEqual(self.run_check(environment).returncode, 0)

            environment = self.base_environment(Path(directory))
            differential = json.loads(Path(environment["PARITY_REPORT"]).read_text())
            differential["scenario_manifest_sha256"] = "0" * 64
            Path(environment["PARITY_REPORT"]).write_text(json.dumps(differential))
            self.assertNotEqual(self.run_check(environment).returncode, 0)


    def test_rejects_nonfinite_metrics_and_evidence_age(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for invalid in [float("nan"), float("inf"), -float("inf")]:
                with self.subTest(metric=invalid):
                    environment = self.base_environment(Path(directory))
                    path = Path(environment["PARITY_PERF_REPORT"])
                    performance = json.loads(path.read_text())
                    performance["profiles"]["rest"]["summary"]["rust"]["p95_latency_ms"] = invalid
                    path.write_text(json.dumps(performance))
                    self.assertNotEqual(self.run_check(environment).returncode, 0)
                with self.subTest(age=invalid):
                    environment = self.base_environment(Path(directory))
                    environment["DOORMAN_RELEASE_EVIDENCE_MAX_AGE_HOURS"] = str(invalid)
                    self.assertNotEqual(self.run_check(environment).returncode, 0)

    def test_rejects_incomplete_operation_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.base_environment(Path(directory))
            path = Path(environment["PARITY_REPORT"])
            differential = json.loads(path.read_text())
            differential["operation_matrix"]["results"].pop()
            path.write_text(json.dumps(differential))
            completed = self.run_check(environment)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("each pinned operation exactly once", completed.stderr)

    def test_rejects_incomplete_system_e2e_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.base_environment(Path(directory))
            path = Path(environment["SYSTEM_E2E_REPORT"])
            report = json.loads(path.read_text())
            report["scenario_counts"]["skipped"] = 1
            path.write_text(json.dumps(report))
            completed = self.run_check(environment)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("without skips", completed.stderr)

    def test_rejects_evidence_for_a_different_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self.base_environment(Path(directory))
            environment["RELEASE_IMAGE_ID"] = "sha256:" + "b" * 64
            completed = self.run_check(environment)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("RELEASE_IMAGE_ID", completed.stderr)

            environment = self.base_environment(Path(directory))
            path = Path(environment["SYSTEM_E2E_REPORT"])
            report = json.loads(path.read_text())
            report["candidate_image_id"] = "sha256:" + "c" * 64
            path.write_text(json.dumps(report))
            completed = self.run_check(environment)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("SYSTEM_E2E_REPORT was not generated for RELEASE_IMAGE_ID", completed.stderr)


if __name__ == "__main__":
    unittest.main()
