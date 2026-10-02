#!/usr/bin/env python3
"""Compare deterministic public wire behavior between Python and Rust gateways."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


VOLATILE_KEYS = {
    "request_id",
    "x-request-id",
    "x-upstream-request-id",
    "timestamp",
    "created_at",
    "updated_at",
    "iat",
    "exp",
    "jti",
}
COMPARED_HEADERS = {
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "allow",
    "content-encoding",
    "content-type",
    "grpc-encoding",
    "grpc-message",
    "grpc-status",
    "retry-after",
    "vary",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-request-id",
}
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}
OPERATION_PROBE_PROFILE = "authenticated-required-parameters-no-body-v1"


def normalize(value: Any, key: str = "") -> Any:
    if key.lower() in VOLATILE_KEYS:
        return "<volatile>"
    if isinstance(value, dict):
        return {item_key: normalize(item, item_key) for item_key, item in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if key.lower() == "vary" and isinstance(value, str):
        return ", ".join(sorted(token.strip().lower() for token in value.split(",")))
    return value


def request(base_url: str, case: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    headers = dict(case.get("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if "json" in case:
        data = json.dumps(case["json"], separators=(",", ":")).encode()
        headers.setdefault("Content-Type", "application/json")
    elif "raw_body" in case:
        data = case["raw_body"].encode()
    outgoing = urllib.request.Request(
        base_url.rstrip("/") + case["path"],
        data=data,
        headers=headers,
        method=case.get("method", "GET"),
    )
    try:
        response = urllib.request.urlopen(outgoing, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    except (TimeoutError, urllib.error.URLError, ConnectionError) as error:
        # A server that never answers is a result to compare, not a crash
        # (e.g. the pinned server hangs on some multipart uploads).
        return {"status": 599, "headers": {}, "body": f"no response: {type(error).__name__}"}
    raw = response.read()
    content_type = response.headers.get_content_type()
    if content_type == "application/json" and raw:
        body: Any = json.loads(raw or b"null")
    else:
        body = raw.decode("utf-8", errors="replace")
    selected_headers = {
        name.lower(): value
        for name, value in response.headers.items()
        if name.lower() in COMPARED_HEADERS
    }
    return normalize(
        {
            "status": response.status,
            "headers": selected_headers,
            "body": body,
        }
    )


def load_openapi(path: Path) -> tuple[bytes, dict[str, Any]]:
    artifact = path.read_bytes()
    try:
        document = json.loads(gzip.decompress(base64.b64decode(artifact)))
    except (ValueError, OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid pinned OpenAPI artifact {path}: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("pinned OpenAPI artifact must contain a paths object")
    return artifact, document


def resolve_local_ref(document: dict[str, Any], value: Any) -> Any:
    while isinstance(value, dict) and set(value) == {"$ref"}:
        reference = value["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise ValueError(f"unsupported OpenAPI reference: {reference!r}")
        resolved: Any = document
        for token in reference[2:].split("/"):
            resolved = resolved[token.replace("~1", "/").replace("~0", "~")]
        value = resolved
    return value


def parameter_value(parameter: dict[str, Any], document: dict[str, Any]) -> str:
    name = str(parameter.get("name", "value")).lower()
    schema = resolve_local_ref(document, parameter.get("schema", {}))
    if isinstance(schema, dict):
        if schema.get("enum"):
            return str(schema["enum"][0])
        if "default" in schema:
            return str(schema["default"])
        kind = schema.get("type")
        if kind in {"integer", "number"}:
            return "1"
        if kind == "boolean":
            return "false"
    if "email" in name:
        return "missing@example.invalid"
    if "method" in name:
        return "GET"
    if "version" in name:
        return "v0"
    return "__parity_missing__"


def operation_cases(document: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for path_template, path_item_value in document["paths"].items():
        path_item = resolve_local_ref(document, path_item_value)
        if not isinstance(path_item, dict):
            raise ValueError(f"OpenAPI path item must be an object: {path_template}")
        for method, operation_value in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            operation = resolve_local_ref(document, operation_value)
            parameters = [
                resolve_local_ref(document, parameter)
                for parameter in [
                    *(path_item.get("parameters") or []),
                    *(operation.get("parameters") or []),
                ]
            ]
            rendered_path = path_template
            query: list[tuple[str, str]] = []
            headers: dict[str, str] = {"Accept": "application/json"}
            for parameter in parameters:
                if not isinstance(parameter, dict) or not parameter.get("required"):
                    continue
                location = parameter.get("in")
                name = str(parameter.get("name"))
                value = parameter_value(parameter, document)
                if location == "path":
                    rendered_path = rendered_path.replace(
                        "{" + name + "}", urllib.parse.quote(value, safe="")
                    )
                elif location == "query":
                    query.append((name, value))
                elif location == "header" and name.lower() != "authorization":
                    headers[name] = value
            if re.search(r"\{[^}]+\}", rendered_path):
                raise ValueError(f"unresolved OpenAPI path parameter: {rendered_path}")
            if query:
                rendered_path += "?" + urllib.parse.urlencode(query)
            cases.append(
                {
                    "name": f"operation:{method.upper()}:{path_template}",
                    "method": method.upper(),
                    "path": rendered_path,
                    "path_template": path_template,
                    "operation_id": operation.get("operationId"),
                    "headers": headers,
                }
            )
    # The invalidate endpoint revokes the token used by this disposable matrix.
    # Keep it last so every other operation receives the same authenticated probe.
    return sorted(
        cases,
        key=lambda case: (
            case["path_template"] == "/platform/authorization/invalidate",
            case["path_template"],
            case["method"],
        ),
    )


def operation_signature(result: dict[str, Any]) -> dict[str, Any]:
    headers = result.get("headers", {})
    content_type = str(headers.get("content-type", "")).split(";", 1)[0].strip().lower()
    allow = sorted(
        token.strip().upper()
        for token in str(headers.get("allow", "")).split(",")
        if token.strip()
    )
    return {"status": result.get("status"), "content_type": content_type, "allow": allow}


def load_operation_approvals(path: Path) -> tuple[bytes, dict[str, str]]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or not all(
        isinstance(name, str) and isinstance(reason, str) and reason.strip()
        for name, reason in value.items()
    ):
        raise ValueError("operation approvals must be an object of probe names to rationales")
    return raw, value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-url", default="http://127.0.0.1:3102")
    parser.add_argument("--rust-url", default="http://127.0.0.1:3101")
    parser.add_argument(
        "--scenarios",
        type=Path,
        default=Path("parity/differential/scenarios.json"),
    )
    parser.add_argument(
        "--openapi-artifact",
        type=Path,
        default=Path("parity/openapi/python-openapi.json.gz.b64"),
    )
    parser.add_argument(
        "--operation-approvals",
        type=Path,
        default=Path("parity/differential/operation_approvals.json"),
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    python_token = os.environ.get("PYTHON_PARITY_TOKEN", "").strip()
    rust_token = os.environ.get("RUST_PARITY_TOKEN", "").strip()
    if not python_token or not rust_token:
        raise ValueError(
            "PYTHON_PARITY_TOKEN and RUST_PARITY_TOKEN are required for the operation matrix"
        )

    scenario_bytes = args.scenarios.read_bytes()
    scenarios = json.loads(scenario_bytes)
    if not isinstance(scenarios, list) or not all(
        isinstance(case, dict) and isinstance(case.get("name"), str) and case["name"]
        for case in scenarios
    ):
        raise ValueError("scenario manifest must be a list of named objects")
    scenario_names = [case["name"] for case in scenarios]
    if len(set(scenario_names)) != len(scenario_names):
        raise ValueError("scenario manifest contains duplicate names")
    results: list[dict[str, Any]] = []
    for case in scenarios:
        python_result = request(args.python_url, case)
        rust_result = request(args.rust_url, case)
        approved_divergence = case.get("approved_rust_divergence")
        results.append(
            {
                "name": case["name"],
                "match": python_result == rust_result,
                "python": python_result,
                "rust": rust_result,
                "approved_divergence": approved_divergence,
            }
        )

    openapi_case = next(
        (
            case
            for case in scenarios
            if case.get("method", "GET") == "GET"
            and case.get("path") == "/platform/openapi.json"
        ),
        {},
    )
    python_openapi = request(
        args.python_url, {"name": "openapi", "path": "/platform/openapi.json"}
    )
    rust_openapi = request(
        args.rust_url, {"name": "openapi", "path": "/platform/openapi.json"}
    )
    results.append(
        {
            "name": "openapi",
            "match": python_openapi == rust_openapi,
            "python": python_openapi,
            "rust": rust_openapi,
            "approved_divergence": openapi_case.get("approved_rust_divergence"),
        }
    )

    openapi_bytes, openapi_document = load_openapi(args.openapi_artifact)
    approval_bytes, operation_approvals = load_operation_approvals(args.operation_approvals)
    matrix_results: list[dict[str, Any]] = []
    cases = operation_cases(openapi_document)
    case_names = {case["name"] for case in cases}
    unknown_approvals = sorted(set(operation_approvals) - case_names)
    if unknown_approvals:
        raise ValueError(
            "operation approvals contain unknown probes: " + ", ".join(unknown_approvals)
        )
    for case in cases:
        python_result = request(args.python_url, case, python_token)
        rust_result = request(args.rust_url, case, rust_token)
        python_signature = operation_signature(python_result)
        rust_signature = operation_signature(rust_result)
        matrix_results.append(
            {
                "name": case["name"],
                "method": case["method"],
                "path_template": case["path_template"],
                "operation_id": case["operation_id"],
                "probe_depth": "authenticated_synthetic_boundary",
                "match": python_signature == rust_signature,
                "python_signature": python_signature,
                "rust_signature": rust_signature,
                "python": python_result,
                "rust": rust_result,
                "approved_divergence": operation_approvals.get(case["name"]),
            }
        )

    curated_differences = sum(
        not result["match"] and not result.get("approved_divergence") for result in results
    )
    matrix_differences = sum(
        not result["match"] and not result.get("approved_divergence")
        for result in matrix_results
    )
    approved_differences = sum(
        not result["match"] and bool(result.get("approved_divergence"))
        for result in [*results, *matrix_results]
    )
    stale_operation_approvals = [
        result["name"]
        for result in matrix_results
        if result["match"] and result.get("approved_divergence")
    ]
    if stale_operation_approvals:
        raise ValueError(
            "operation approvals now match and must be removed: "
            + ", ".join(stale_operation_approvals)
        )

    report = {
        "schema_version": 1,
        "scenario_manifest_sha256": hashlib.sha256(scenario_bytes).hexdigest(),
        "openapi_artifact_sha256": hashlib.sha256(openapi_bytes).hexdigest(),
        "operation_approvals_sha256": hashlib.sha256(approval_bytes).hexdigest(),
        "probe_profile": OPERATION_PROBE_PROFILE,
        "differences": curated_differences + matrix_differences,
        "approved_differences": approved_differences,
        "results": results,
        "operation_matrix": {
            "operation_count": len(matrix_results),
            "differences": matrix_differences,
            "results": matrix_results,
        },
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for result in results:
        label = "PASS" if result["match"] else "APPROVED" if result.get("approved_divergence") else "FAIL"
        print(f"{label} {result['name']}")
        if not result["match"]:
            if result.get("approved_divergence"):
                print("  approved:", result["approved_divergence"])
            python_display = json.dumps(result["python"], sort_keys=True)
            rust_display = json.dumps(result["rust"], sort_keys=True)
            print("  python:", python_display[:2000] + ("..." if len(python_display) > 2000 else ""))
            print("  rust:  ", rust_display[:2000] + ("..." if len(rust_display) > 2000 else ""))
    for result in matrix_results:
        if result["match"]:
            continue
        label = "APPROVED" if result.get("approved_divergence") else "FAIL"
        print(f"{label} {result['name']}")
        if result.get("approved_divergence"):
            print("  approved:", result["approved_divergence"])
        print("  python signature:", json.dumps(result["python_signature"], sort_keys=True))
        print("  rust signature:  ", json.dumps(result["rust_signature"], sort_keys=True))
    print(
        f"operation_matrix={len(matrix_results)} "
        f"operation_differences={matrix_differences}"
    )
    print(f"differences={report['differences']} approved_differences={report['approved_differences']}")
    return 1 if report["differences"] else 0


if __name__ == "__main__":
    sys.exit(main())
