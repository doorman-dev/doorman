#!/usr/bin/env python3
"""Generate and validate the pinned Python-to-Rust source coverage ledger."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATH = ROOT / "parity/reference.json"
OVERRIDES_PATH = ROOT / "parity/source_coverage_overrides.json"
LEDGER_PATH = ROOT / "parity/source_coverage_ledger.json"
VALID_STATUSES = {
    "translated",
    "partial",
    "missing",
    "approved_changed",
    "approved_obsolete",
    "unreviewed",
}


def git_text(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True)


def pinned_source_paths(commit: str) -> list[str]:
    paths = git_text("ls-tree", "-r", "--name-only", commit, "--", "backend-services").splitlines()
    return sorted(
        path
        for path in paths
        if path.endswith(".py")
        and not path.startswith("backend-services/tests/")
        and not path.startswith("backend-services/live-tests/")
        and "/__pycache__/" not in path
    )


def domain_for(path: str) -> str:
    relative = Path(path).relative_to("backend-services")
    if len(relative.parts) == 1:
        return "application"
    return "/".join(relative.parts[:-1])


def decorator_names(node: ast.AST) -> list[str]:
    decorators = getattr(node, "decorator_list", [])
    return [ast.unparse(decorator) for decorator in decorators]


@dataclass(frozen=True)
class SourceUnit:
    kind: str
    name: str
    line: int
    decorators: tuple[str, ...] = ()


class UnitVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.parents: list[tuple[str, str]] = []
        self.units: list[SourceUnit] = []

    def qualified(self, name: str) -> str:
        return ".".join([*(parent[0] for parent in self.parents), name])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.units.append(
            SourceUnit("class", self.qualified(node.name), node.lineno, tuple(decorator_names(node)))
        )
        self.parents.append((node.name, "class"))
        for statement in node.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        self.units.append(SourceUnit("field", self.qualified(target.id), statement.lineno))
            self.visit(statement)
        self.parents.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        parent_kind = self.parents[-1][1] if self.parents else ""
        kind = "method" if parent_kind == "class" else "function"
        self.units.append(
            SourceUnit(kind, self.qualified(node.name), node.lineno, tuple(decorator_names(node)))
        )
        self.parents.append((node.name, kind))
        self.generic_visit(node)
        self.parents.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        parent_kind = self.parents[-1][1] if self.parents else ""
        kind = "async_method" if parent_kind == "class" else "async_function"
        self.units.append(
            SourceUnit(kind, self.qualified(node.name), node.lineno, tuple(decorator_names(node)))
        )
        self.parents.append((node.name, kind))
        self.generic_visit(node)
        self.parents.pop()


def source_units(source: str, path: str) -> Iterator[SourceUnit]:
    module = ast.parse(source, filename=path)
    yield SourceUnit("module", Path(path).stem, 1)
    visitor = UnitVisitor()
    visitor.visit(module)
    yield from visitor.units


def load_overrides() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    data = json.loads(OVERRIDES_PATH.read_text())
    if (
        data.get("schema_version") != 1
        or not isinstance(data.get("entries"), dict)
        or not isinstance(data.get("file_defaults", {}), dict)
    ):
        raise ValueError(
            "source coverage overrides must contain schema_version=1, entries, and optional file_defaults"
        )
    return data["entries"], data.get("file_defaults", {})


def validate_override(unit_id: str, override: dict[str, Any]) -> None:
    status = override.get("status")
    if status not in VALID_STATUSES - {"unreviewed"}:
        raise ValueError(f"{unit_id}: invalid reviewed status {status!r}")
    rust_symbols = override.get("rust_symbols", [])
    rust_tests = override.get("rust_tests", [])
    if not isinstance(rust_symbols, list) or not all(isinstance(item, str) for item in rust_symbols):
        raise ValueError(f"{unit_id}: rust_symbols must be a list of strings")
    if not isinstance(rust_tests, list) or not all(isinstance(item, str) for item in rust_tests):
        raise ValueError(f"{unit_id}: rust_tests must be a list of strings")
    if status == "translated" and (not rust_symbols or not rust_tests):
        raise ValueError(f"{unit_id}: translated units require Rust symbols and assertion-level tests")
    if status == "partial" and not (rust_symbols or rust_tests):
        raise ValueError(f"{unit_id}: partial units require existing Rust evidence")
    if status.startswith("approved_") and not override.get("rationale"):
        raise ValueError(f"{unit_id}: approved dispositions require a rationale")


def build_ledger() -> dict[str, Any]:
    reference = json.loads(REFERENCE_PATH.read_text())
    commit = reference["commit"]
    overrides, file_defaults = load_overrides()
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    used_file_defaults: set[str] = set()

    for path, override in file_defaults.items():
        validate_override(f"{path}::*", override)

    for path in pinned_source_paths(commit):
        source = git_text("show", f"{commit}:{path}")
        occurrences: Counter[str] = Counter()
        for unit in source_units(source, path):
            base_id = f"{path}::{unit.kind}:{unit.name}"
            occurrences[base_id] += 1
            unit_id = base_id if occurrences[base_id] == 1 else f"{base_id}#{occurrences[base_id]}"
            if unit_id in seen:
                raise ValueError(f"duplicate source unit ID: {unit_id}")
            seen.add(unit_id)
            override = overrides.pop(unit_id, None)
            if override is None and path in file_defaults:
                override = file_defaults[path]
                used_file_defaults.add(path)
            if override is None:
                override = {
                    "status": "unreviewed",
                    "rust_symbols": [],
                    "rust_tests": [],
                    "notes": "Not yet reviewed against the pinned Python source.",
                }
            else:
                validate_override(unit_id, override)
            entries.append(
                {
                    "id": unit_id,
                    "source": {"path": path, "line": unit.line, "kind": unit.kind},
                    "domain": domain_for(path),
                    "decorators": list(unit.decorators),
                    "status": override["status"],
                    "rust_symbols": override.get("rust_symbols", []),
                    "rust_tests": override.get("rust_tests", []),
                    "notes": override.get("notes", ""),
                    **({"rationale": override["rationale"]} if "rationale" in override else {}),
                }
            )

    if overrides:
        unknown = ", ".join(sorted(overrides)[:10])
        raise ValueError(f"overrides refer to units absent from the pinned reference: {unknown}")
    unused_file_defaults = set(file_defaults) - used_file_defaults
    if unused_file_defaults:
        unknown = ", ".join(sorted(unused_file_defaults)[:10])
        raise ValueError(f"file defaults refer to files absent from the pinned reference: {unknown}")

    status_counts = Counter(entry["status"] for entry in entries)
    domain_counts: dict[str, Counter[str]] = defaultdict(Counter)
    kind_counts = Counter(entry["source"]["kind"] for entry in entries)
    for entry in entries:
        domain_counts[entry["domain"]][entry["status"]] += 1
    reviewed = len(entries) - status_counts["unreviewed"]

    return {
        "schema_version": 1,
        "reference": {"git_ref": reference["git_ref"], "commit": commit},
        "generation": {
            "command": "python3 scripts/generate_source_coverage_ledger.py --write",
            "status_values": sorted(VALID_STATUSES),
        },
        "summary": {
            "total_source_units": len(entries),
            "reviewed_source_units": reviewed,
            "reviewed_percent": round(reviewed * 100 / len(entries), 2) if entries else 100.0,
            "status_counts": dict(sorted(status_counts.items())),
            "kind_counts": dict(sorted(kind_counts.items())),
            "domain_status_counts": {
                domain: dict(sorted(counts.items())) for domain, counts in sorted(domain_counts.items())
            },
        },
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate the checked-in ledger")
    mode.add_argument("--check", action="store_true", help="verify the checked-in ledger is current")
    args = parser.parse_args()

    try:
        ledger = build_ledger()
    except (OSError, ValueError, subprocess.CalledProcessError, SyntaxError) as error:
        print(f"source coverage ledger error: {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    if args.write:
        LEDGER_PATH.write_text(rendered)
        summary = ledger["summary"]
        print(
            f"wrote {LEDGER_PATH.relative_to(ROOT)} with "
            f"{summary['total_source_units']} source units"
        )
        return 0

    if not LEDGER_PATH.exists() or LEDGER_PATH.read_text() != rendered:
        print(
            "source coverage ledger is stale; run "
            "python3 scripts/generate_source_coverage_ledger.py --write",
            file=sys.stderr,
        )
        return 1

    summary = ledger["summary"]
    print(
        "source coverage ledger verified:",
        f"units={summary['total_source_units']}",
        f"reviewed={summary['reviewed_source_units']}",
        f"reviewed_percent={summary['reviewed_percent']}",
        " ".join(f"{status}={count}" for status, count in summary["status_counts"].items()),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
