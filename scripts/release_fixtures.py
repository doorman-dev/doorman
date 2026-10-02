#!/usr/bin/env python3
"""Owned Docker fixtures and recovery rehearsals for ``make release-e2e``.

Everything created here has a random, invocation-specific name. The harness uses
the pinned Python commit from ``parity/reference.json`` and the immutable Rust
image ID built by the calling runner. It never reads or mounts deployment data.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import secrets
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROTO = """syntax = "proto3";
package releasegrpc_v1;
service Resource {
  rpc Create (CreateRequest) returns (CreateReply);
}
message CreateRequest { string name = 1; }
message CreateReply { string message = 1; }
"""
SOAP_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soap:Body><Ping xmlns="urn:doorman:release"/></soap:Body></soap:Envelope>'
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def performance_scenarios(python_url: str, rust_url: str) -> list[dict[str, Any]]:
    return [
        {
            "name": "rest",
            "python_url": f"{python_url}/api/rest/release-rest/v1/rest",
            "rust_url": f"{rust_url}/api/rest/release-rest/v1/rest",
        },
        {
            "name": "graphql",
            "python_url": f"{python_url}/api/graphql/release-graphql",
            "rust_url": f"{rust_url}/api/graphql/release-graphql",
            "request": {
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    "X-API-Version": "v1",
                },
                "body": json.dumps({"query": "{ hello }"}, separators=(",", ":")),
            },
        },
        {
            "name": "soap",
            "python_url": f"{python_url}/api/soap/release-soap/v1/soap",
            "rust_url": f"{rust_url}/api/soap/release-soap/v1/soap",
            "request": {
                "method": "POST",
                "headers": {"Content-Type": "text/xml", "SOAPAction": "Ping"},
                "body": SOAP_BODY,
            },
        },
        {
            "name": "grpc",
            "python_url": f"{python_url}/api/grpc/releasegrpc",
            "rust_url": f"{rust_url}/api/grpc/releasegrpc",
            "request": {
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    "X-API-Version": "v1",
                },
                "body": json.dumps(
                    {
                        "method": "Resource.Create",
                        "message": {"name": "release-fixture"},
                    },
                    separators=(",", ":"),
                ),
            },
        },
    ]


class ReleaseFixtures:
    def __init__(self, evidence: Path, rust_image_id: str, environment: dict[str, str]):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", rust_image_id):
            raise ValueError("release fixtures require an immutable Rust image ID")
        self.evidence = evidence
        self.rust_image_id = rust_image_id
        self.parent_env = environment
        self.token = secrets.token_hex(6)
        self.prefix = f"doorman-release-{self.token}"
        self.containers: list[str] = []
        self.volumes: list[str] = []
        self.python_image_id: str | None = None
        self.log_path = evidence / "release-fixtures.log"
        self.container_log_dir = evidence / "fixture-containers"
        self.container_log_dir.mkdir(exist_ok=True)
        self.admin_email = "release-admin@example.test"
        self.admin_password = "Release!" + secrets.token_hex(24)
        self.jwt_secret = secrets.token_hex(48)
        self.memory_key = secrets.token_hex(32)
        self.upstream_http_port = free_port()
        self.upstream_grpc_port = free_port()
        self.common_env = {
            "ENV": "development",
            "HOST": "127.0.0.1",
            "WEB_HOST": "127.0.0.1",
            "THREADS": "1",
            "MEM_OR_EXTERNAL": "MEM",
            "MEM_AUTO_SAVE_ENABLED": "false",
            "MEM_DUMP_PATH": "/app/data/memory_dump.bin",
            "MEM_ENCRYPTION_KEY": self.memory_key,
            "HTTPS_ONLY": "false",
            "COOKIE_SAMESITE": "Lax",
            "CORS_STRICT": "true",
            "LOCAL_HOST_IP_BYPASS": "false",
            "ALLOWED_ORIGINS": "https://console.example",
            "ALLOW_METHODS": "GET,POST,PUT,DELETE,OPTIONS,PATCH,HEAD",
            "ALLOW_HEADERS": "*",
            "ALLOW_CREDENTIALS": "true",
            "JWT_SECRET_KEY": self.jwt_secret,
            "JWT_ISSUER": "doorman-release-fixture",
            "JWT_AUDIENCE": "doorman-release-clients",
            "DOORMAN_ADMIN_EMAIL": self.admin_email,
            "DOORMAN_ADMIN_PASSWORD": self.admin_password,
            "DEMO_SEED": "false",
        }

    def log(self, message: str) -> None:
        line = f"[{utc_now()}] {message}"
        print(line, flush=True)
        with self.log_path.open("a") as output:
            output.write(line + "\n")

    def command(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 600,
        output_file: Path | None = None,
    ) -> str:
        self.log("running: " + " ".join(args[:3]) + (" ..." if len(args) > 3 else ""))
        completed = subprocess.run(
            args,
            cwd=ROOT,
            env=env or self.parent_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        if output_file is not None:
            output_file.write_text(completed.stdout)
        if completed.returncode:
            tail = "\n".join(completed.stdout.splitlines()[-30:])
            raise RuntimeError(f"fixture command failed: {args[0]} {args[1]}\n{tail}")
        return completed.stdout.strip()

    def build_python_reference(self) -> None:
        reference = json.loads((ROOT / "parity/reference.json").read_text())
        commit = reference["commit"]
        with tempfile.TemporaryDirectory(prefix="doorman-python-reference-") as directory:
            context = Path(directory)
            archive = subprocess.run(
                ["git", "archive", "--format=tar", commit, "backend-services"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if archive.returncode:
                raise RuntimeError("could not export the pinned Python reference")
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as bundle:
                root = context.resolve()
                for member in bundle.getmembers():
                    target = (context / member.name).resolve()
                    if root not in target.parents and target != root:
                        raise RuntimeError("unsafe path in pinned Python archive")
                bundle.extractall(context, filter="data")
            (context / "Dockerfile").write_text(
                """FROM python:3.12-slim-bookworm
RUN apt-get update \\
 && apt-get install -y --no-install-recommends build-essential curl libprotobuf-dev protobuf-compiler \\
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app/backend-services
COPY backend-services/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY backend-services /app/backend-services
ENV PYTHONUNBUFFERED=1
CMD ["python", "doorman.py"]
"""
            )
            iid = context / "python-image-id.txt"
            self.command(
                ["docker", "build", "--provenance=false", "--iidfile", str(iid), str(context)],
                timeout=1800,
                output_file=self.evidence / "python-reference-image-build.log",
            )
            image_id = iid.read_text().strip()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                raise RuntimeError("Docker did not produce a pinned Python image ID")
            self.python_image_id = image_id
        self.log(f"built pinned Python reference {commit[:12]} as {self.python_image_id}")

    def create_volume(self, suffix: str) -> str:
        name = f"{self.prefix}-{suffix}"
        self.command(["docker", "volume", "create", name])
        self.volumes.append(name)
        return name

    def start_upstreams(self) -> None:
        assert self.python_image_id
        name = f"{self.prefix}-upstream"
        command = [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            "host",
            "--env",
            "FIXTURE_HTTP_PORT",
            "--env",
            "FIXTURE_GRPC_PORT",
            "--volume",
            f"{ROOT / 'scripts/release_fixture_upstreams.py'}:/fixture.py:ro",
            self.python_image_id,
            "python",
            "/fixture.py",
        ]
        self.command(
            command,
            env={
                **self.parent_env,
                "FIXTURE_HTTP_PORT": str(self.upstream_http_port),
                "FIXTURE_GRPC_PORT": str(self.upstream_grpc_port),
            },
        )
        self.containers.append(name)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            output = self.command(["docker", "logs", name], timeout=30)
            if "release fixture upstreams ready" in output:
                return
            time.sleep(1)
        raise RuntimeError("release protocol upstreams did not become ready")

    def start_gateway(
        self,
        implementation: str,
        suffix: str,
        volume: str,
        *,
        python_proto_volume: str | None = None,
        python_generated_volume: str | None = None,
    ) -> tuple[str, str]:
        image = self.python_image_id if implementation == "python" else self.rust_image_id
        assert image
        name = f"{self.prefix}-{suffix}"
        port = free_port()
        web_port = free_port()
        gateway_env = {**self.common_env, "PORT": str(port), "WEB_PORT": str(web_port)}
        child_env = {**self.parent_env, **gateway_env}
        command = [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            "host",
            "--volume",
            f"{volume}:/app/data",
        ]
        if implementation == "python" and python_proto_volume and python_generated_volume:
            command.extend(
                [
                    "--volume",
                    f"{python_proto_volume}:/app/backend-services/proto",
                    "--volume",
                    f"{python_generated_volume}:/app/backend-services/generated",
                ]
            )
        for key in gateway_env:
            command.extend(["--env", key])
        command.append(image)
        self.command(command, env=child_env)
        self.containers.append(name)
        base_url = f"http://127.0.0.1:{port}"
        self.wait_gateway(base_url)
        return name, base_url

    def wait_gateway(self, base_url: str) -> None:
        deadline = time.monotonic() + 180
        last = "no response"
        while time.monotonic() < deadline:
            status, _body = self.request(
                base_url, "GET", "/api/health", expected=None, timeout=3
            )
            if status == 200:
                return
            last = f"HTTP {status}"
            time.sleep(1)
        raise RuntimeError(f"release gateway did not become ready: {last}")

    def request(
        self,
        base_url: str,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json_body: Any | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: set[int] | None = None,
        timeout: int = 20,
    ) -> tuple[int, Any]:
        outgoing_headers = dict(headers or {})
        data = raw_body
        if json_body is not None:
            data = json.dumps(json_body, separators=(",", ":")).encode()
            outgoing_headers.setdefault("Content-Type", "application/json")
        if token:
            outgoing_headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            base_url.rstrip("/") + path,
            data=data,
            headers=outgoing_headers,
            method=method,
        )
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, TimeoutError, urllib.error.URLError):
            return 0, None
        raw = response.read()
        try:
            body: Any = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = raw.decode(errors="replace")
        if expected is not None and response.status not in expected:
            raise RuntimeError(f"{method} {path} returned HTTP {response.status}: {body}")
        return response.status, body

    @staticmethod
    def unwrap(value: Any) -> Any:
        while isinstance(value, dict) and set(value).intersection({"response"}):
            nested = value.get("response")
            if nested is value:
                break
            value = nested
        return value

    def login(self, base_url: str) -> str:
        _status, body = self.request(
            base_url,
            "POST",
            "/platform/authorization",
            json_body={"email": self.admin_email, "password": self.admin_password},
            expected={200},
        )
        value = self.unwrap(body)
        token = value.get("access_token") if isinstance(value, dict) else None
        if not isinstance(token, str) or not token:
            raise RuntimeError("release fixture login did not return an access token")
        return token

    def upload_proto(self, base_url: str, token: str) -> None:
        boundary = "----doorman-release-" + secrets.token_hex(12)
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="release.proto"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + PROTO.encode() + f"\r\n--{boundary}--\r\n".encode()
        self.request(
            base_url,
            "POST",
            "/platform/proto/releasegrpc/v1",
            token=token,
            raw_body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            expected={200, 201},
        )

    def seed(self, base_url: str) -> None:
        token = self.login(base_url)
        definitions = [
            ("release-rest", "REST", "/rest", {}),
            ("release-graphql", "GRAPHQL", "/graphql", {}),
            ("release-soap", "SOAP", "/soap", {}),
            ("releasegrpc", "GRPC", "/grpc", {"api_grpc_package": "releasegrpc_v1"}),
        ]
        for name, protocol, path, extra in definitions:
            server = (
                f"grpc://127.0.0.1:{self.upstream_grpc_port}"
                if protocol == "GRPC"
                else f"http://127.0.0.1:{self.upstream_http_port}"
            )
            payload = {
                "api_name": name,
                "api_version": "v1",
                "api_description": f"isolated release {protocol} fixture",
                "api_allowed_roles": [],
                "api_allowed_groups": [],
                "api_servers": [server],
                "api_type": protocol,
                "api_allowed_retry_count": 0,
                "api_public": True,
                "active": True,
                **extra,
            }
            self.request(
                base_url,
                "POST",
                "/platform/api",
                token=token,
                json_body=payload,
                expected={200, 201},
            )
            if protocol == "GRPC":
                self.upload_proto(base_url, token)
            self.request(
                base_url,
                "POST",
                "/platform/endpoint",
                token=token,
                json_body={
                    "api_name": name,
                    "api_version": "v1",
                    "endpoint_method": "GET" if protocol == "REST" else "POST",
                    "endpoint_uri": path,
                    "endpoint_description": f"isolated {protocol} endpoint",
                },
                expected={200, 201},
            )
        self.verify(base_url)

    def verify(self, base_url: str) -> None:
        token = self.login(base_url)
        for name in ("release-rest", "release-graphql", "release-soap", "releasegrpc"):
            self.request(
                base_url,
                "GET",
                f"/platform/api/{name}/v1",
                token=token,
                expected={200},
            )
        scenarios = performance_scenarios(base_url, base_url)
        for scenario in scenarios:
            request_data = scenario.get("request", {})
            self.request(
                base_url,
                request_data.get("method", "GET"),
                scenario["python_url"].removeprefix(base_url),
                raw_body=(request_data.get("body") or "").encode() or None,
                headers=request_data.get("headers", {}),
                expected={200},
            )

    def dump_memory(self, base_url: str) -> str:
        token = self.login(base_url)
        _status, body = self.request(
            base_url,
            "POST",
            "/platform/memory/dump",
            token=token,
            json_body={},
            expected={200},
        )
        value = self.unwrap(body)
        if isinstance(value, dict) and isinstance(value.get("path"), str):
            return value["path"]
        raise RuntimeError("memory dump did not return its snapshot path")

    def remove_container(self, name: str, *, stop: bool = True) -> None:
        if name not in self.containers:
            return
        if stop:
            self.command(["docker", "stop", "--time", "45", name], timeout=60)
        try:
            logs = self.command(["docker", "logs", name], timeout=60)
            (self.container_log_dir / f"{name}.log").write_text(logs + "\n")
        except (OSError, RuntimeError, subprocess.SubprocessError):
            pass
        self.command(["docker", "rm", "--force", name], timeout=60)
        self.containers.remove(name)

    def container_pid(self, name: str, process: str | None = None) -> str:
        if process:
            output = self.command(["docker", "top", name, "-eo", "pid,args"], timeout=30)
            for line in output.splitlines()[1:]:
                fields = line.strip().split(maxsplit=1)
                if len(fields) == 2 and process in fields[1] and fields[0].isdigit():
                    return fields[0]
            raise RuntimeError(f"could not resolve {process} PID for {name}")
        value = self.command(
            ["docker", "inspect", "--format", "{{.State.Pid}}", name], timeout=30
        )
        if not value.isdigit() or int(value) <= 0:
            raise RuntimeError(f"could not resolve host PID for {name}")
        return value

    def prepare_data_volume_for_rust(self, volume: str) -> None:
        self.command(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "0:0",
                "--entrypoint",
                "chown",
                "--volume",
                f"{volume}:/app/data",
                self.rust_image_id,
                "-R",
                "10001:10001",
                "/app/data",
            ],
            timeout=60,
        )

    def rehearse_operations(self) -> dict[str, Any]:
        volume = self.create_volume("operations-data")
        proto_volume = self.create_volume("operations-python-proto")
        generated_volume = self.create_volume("operations-python-generated")
        python, python_url = self.start_gateway(
            "python",
            "ops-python",
            volume,
            python_proto_volume=proto_volume,
            python_generated_volume=generated_volume,
        )
        self.seed(python_url)
        python_snapshot = self.dump_memory(python_url)
        self.remove_container(python)

        restored_python, restored_python_url = self.start_gateway(
            "python",
            "ops-python-restore",
            volume,
            python_proto_volume=proto_volume,
            python_generated_volume=generated_volume,
        )
        self.verify(restored_python_url)
        self.remove_container(restored_python)

        self.prepare_data_volume_for_rust(volume)
        rust, rust_url = self.start_gateway("rust", "ops-rust", volume)
        self.verify(rust_url)
        rust_snapshot = self.dump_memory(rust_url)
        self.remove_container(rust)

        rollback, rollback_url = self.start_gateway(
            "python",
            "ops-python-rollback",
            volume,
            python_proto_volume=proto_volume,
            python_generated_volume=generated_volume,
        )
        self.verify(rollback_url)
        self.remove_container(rollback)
        reference = json.loads((ROOT / "parity/reference.json").read_text())
        return {
            "schema_version": 1,
            "image_id": self.rust_image_id,
            "image_smoke": {
                "passed": True,
                "image_id": self.rust_image_id,
                "scope": "disposable loopback candidate",
            },
            "restore_rehearsal": {
                "passed": True,
                "snapshot": python_snapshot,
                "verified_resources": [
                    "release-rest",
                    "release-graphql",
                    "release-soap",
                    "releasegrpc",
                ],
            },
            "cutover": {
                "passed": True,
                "python_commit": reference["commit"],
                "rust_image_id": self.rust_image_id,
                "snapshot": python_snapshot,
                "protocols": ["REST", "GraphQL", "SOAP", "gRPC"],
                "fresh_login": True,
                "data_volume_owner": "10001:10001",
            },
            "rollback": {
                "passed": True,
                "python_commit": reference["commit"],
                "rust_snapshot": rust_snapshot,
                "fresh_login": True,
                "protocols": ["REST", "GraphQL", "SOAP", "gRPC"],
            },
            "finished_at": utc_now(),
        }

    def start_comparison_pair(self) -> dict[str, str]:
        python_volume = self.create_volume("comparison-python-data")
        rust_volume = self.create_volume("comparison-rust-data")
        python, python_url = self.start_gateway(
            "python", "compare-python", python_volume
        )
        rust, rust_url = self.start_gateway("rust", "compare-rust", rust_volume)
        self.seed(python_url)
        self.seed(rust_url)
        python_token = self.login(python_url)
        rust_token = self.login(rust_url)
        scenario_path = self.evidence / "performance-scenarios.json"
        scenario_path.write_text(
            json.dumps(performance_scenarios(python_url, rust_url), indent=2) + "\n"
        )
        return {
            "PYTHON_PARITY_URL": python_url,
            "RUST_PARITY_URL": rust_url,
            "PYTHON_PARITY_PID": self.container_pid(python, "python"),
            "RUST_PARITY_PID": self.container_pid(rust, "doorman-gateway"),
            "PYTHON_PARITY_TOKEN": python_token,
            "RUST_PARITY_TOKEN": rust_token,
            "PARITY_PERF_SCENARIOS": str(scenario_path),
        }

    def start(self) -> dict[str, str]:
        self.log("starting isolated release fixture harness")
        self.build_python_reference()
        self.start_upstreams()
        operations = self.rehearse_operations()
        operations_path = self.evidence / "operations.json"
        operations_path.write_text(json.dumps(operations, indent=2, sort_keys=True) + "\n")
        result = self.start_comparison_pair()
        result["RELEASE_OPERATIONS_REPORT"] = str(operations_path)
        self.log("release fixtures and recovery rehearsals passed")
        return result

    def cleanup(self) -> None:
        for name in list(reversed(self.containers)):
            try:
                self.remove_container(name)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                self.log(f"cleanup warning for {name}: {error}")
        for volume in reversed(self.volumes):
            subprocess.run(
                ["docker", "volume", "rm", "--force", volume],
                env=self.parent_env,
                capture_output=True,
                timeout=60,
                check=False,
            )
        self.containers.clear()
        self.volumes.clear()
        self.log("owned release fixture resources removed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id-file", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    fixture = ReleaseFixtures(
        args.evidence.resolve(), args.image_id_file.read_text().strip(), dict(os.environ)
    )
    try:
        values = fixture.start()
        print(
            "release fixture verification passed: "
            + ", ".join(sorted(values)),
            flush=True,
        )
        return 0
    finally:
        fixture.cleanup()


__all__ = ["ReleaseFixtures", "performance_scenarios"]


if __name__ == "__main__":
    raise SystemExit(main())
