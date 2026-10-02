#!/usr/bin/env python3
"""Runtime-setting executor for the comprehensive system E2E corpus.

Each `setting::<NAME>::<positive|invalid>` scenario starts the candidate with
that one setting applied and runs the setting's probe.  For settings the pinned
Python server also reads, the oracle is started with the identical environment
and the two observations (startup outcome plus probe result) must be equal.
Settings only the candidate reads are compared with the documented expectation
recorded in SPEC.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import signal
import socket
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.system_operations import FIXTURE_PROTO, UNLIMITED, Response, json_body, load_approvals, send  # noqa: E402

ORIGIN = "https://system-e2e.invalid"
ADMIN_EMAIL = "settings-admin@example.test"
ADMIN_PASSWORD = "SettingsAdmin!Pass2026"
JWT_SECRET = "settings-jwt-secret-key-0123456789abcdef"
BASE_ENV = {
    "ENV": "development", "HOST": "127.0.0.1", "THREADS": "1", "MEM_OR_EXTERNAL": "MEM",
    "MEM_AUTO_SAVE_ENABLED": "false", "MEM_ENCRYPTION_KEY": "settings-mem-encryption-key-0123456789",
    "DOORMAN_ADMIN_EMAIL": ADMIN_EMAIL, "DOORMAN_ADMIN_PASSWORD": ADMIN_PASSWORD,
    "JWT_SECRET_KEY": JWT_SECRET, "CORS_STRICT": "true", "ALLOWED_ORIGINS": ORIGIN,
    "ALLOW_HEADERS": "*", "ALLOW_METHODS": "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
    "LOCAL_HOST_IP_BYPASS": "false", "HTTPS_ONLY": "false", "DEMO_SEED": "false",
    "LOGIN_IP_RATE_LIMIT": "1000000", "LOGIN_ACCOUNT_RATE_LIMIT": "1000000",
    "DISCOVERY_ALLOWED_HOSTS": "127.0.0.1,localhost",
}
# Settings only the candidate reads (no pinned oracle behaviour to compare).
RUST_ONLY = {"DISCOVERY_ALLOWED_HOSTS", "JWT_AUDIENCE", "JWT_ISSUER", "METRICS_SAVE_INTERVAL"}


@dataclass
class Instance:
    base: str
    workdir: Path
    handle: Any = None


class Launcher(Protocol):
    def start(self, implementation: str, env: dict[str, str]) -> Instance | None: ...
    def stop(self, instance: Instance) -> None: ...


@dataclass
class Context:
    """Upstream fixture addresses: `rest_upstream` as seen by the gateways and
    `rest_control` as reachable from this process (they differ under Docker)."""

    rest_upstream: str
    rest_control: str


# --------------------------------------------------------------------------- helpers


def _login(i: Instance) -> Response:
    body, headers = json_body({"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    return send(i.base, "POST", "/platform/authorization", body=body, headers=headers)


def _token(i: Instance) -> str:
    value = _login(i).json() or {}
    while isinstance(value, dict) and isinstance(value.get("response"), dict):
        value = value["response"]
    return value.get("access_token", "") if isinstance(value, dict) else ""


def _call(i: Instance, method: str, path: str, value: Any = None, token: str | None = None) -> Response:
    body, headers = json_body(value) if value is not None else (None, {})
    return send(i.base, method, path, token=token or _token(i), body=body, headers=headers, timeout=20)


def _claims(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return {}


def _preflight(i: Instance, origin: str = ORIGIN, method: str = "PUT", headers: str = "Content-Type") -> dict[str, Any]:
    response = send(i.base, "OPTIONS", "/platform/api/all", headers={
        "Origin": origin, "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": headers})
    keep = ("access-control-allow-origin", "access-control-allow-credentials")
    return {"status": response.status, **{k: response.headers.get(k) for k in keep}}


def _cookie_attributes(response: Response) -> dict[str, Any]:
    # urllib folds repeated Set-Cookie headers into one comma-joined value.
    raw = response.headers.get("set-cookie", "")
    cookies: dict[str, Any] = {}
    for part in raw.split(", "):
        if "=" not in part.split(";")[0]:
            continue
        name = part.split("=", 1)[0].strip()
        attrs = {}
        for attr in part.split(";")[1:]:
            key, _, value = attr.strip().partition("=")
            key = key.lower()
            if key in ("samesite", "domain", "path"):
                attrs[key] = value.lower()
            elif key in ("secure", "httponly"):
                attrs[key] = True
            elif key == "max-age":
                attrs[key] = round(int(value) / 60) if value.lstrip("-").isdigit() else value
        cookies[name] = attrs
    return cookies


def _ttl_minutes(token: str) -> int | None:
    exp = _claims(token).get("exp")
    return round((exp - time.time()) / 60) if isinstance(exp, (int, float)) else None


def _fixture(ctx: Context, faults: dict[str, Any] | None = None) -> None:
    urllib.request.urlopen(urllib.request.Request(ctx.rest_control + "/__control/reset", data=b"{}", method="POST"), timeout=5).read()
    if faults:
        urllib.request.urlopen(urllib.request.Request(
            ctx.rest_control + "/__control/faults", data=json.dumps(faults).encode(), method="POST"), timeout=5).read()


def _fixture_count(ctx: Context) -> int:
    with urllib.request.urlopen(ctx.rest_control + "/__control/counters", timeout=5) as response:
        return sum(json.load(response).get("counts", {}).values())


def _gateway(i: Instance, ctx: Context, *, faults: dict[str, Any] | None = None, calls: int = 1,
             servers: list[str] | None = None, retry: int = 0, method: str = "GET", body: bytes | None = None,
             kind: str = "REST", subscribe: bool = True) -> dict[str, Any]:
    token = _token(i)
    api = {"api_name": "setapi", "api_version": "v1", "api_servers": servers or [ctx.rest_upstream],
           "api_type": kind, "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"],
           "api_allowed_retry_count": retry, "active": True}
    # The seeded admin allows one request per second; lift it so the probe
    # observes the setting, not the user rate limit.
    _call(i, "PUT", "/platform/user/admin", {k: v for k, v in UNLIMITED.items() if k != "bandwidth_limit_enabled"}, token)
    _call(i, "POST", "/platform/api", api, token)
    _call(i, "POST", "/platform/endpoint", {"api_name": "setapi", "api_version": "v1", "endpoint_method": method,
                                            "endpoint_uri": "/items", "endpoint_description": "settings probe"}, token)
    if subscribe:
        _call(i, "POST", "/platform/subscription/subscribe",
              {"username": "admin", "api_name": "setapi", "api_version": "v1"}, token)
    _fixture(ctx, faults)
    statuses = []
    for _ in range(calls):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        statuses.append(send(i.base, method, "/api/rest/setapi/v1/items", token=token, body=body,
                             headers=headers, timeout=20).status)
    return {"statuses": statuses, "upstream_requests": _fixture_count(ctx)}


def _proto_upload(i: Instance, size: int) -> int:
    token = _token(i)
    _call(i, "POST", "/platform/api", {"api_name": "setproto", "api_version": "v1", "api_type": "GRPC",
                                       "api_servers": ["grpc://127.0.0.1:9"], "api_allowed_roles": ["admin"],
                                       "api_allowed_groups": ["ALL"]}, token)
    proto = FIXTURE_PROTO + "\n//" + "x" * max(0, size - len(FIXTURE_PROTO))
    boundary = "----settings-proto"
    data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"s.proto\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n{proto}\r\n--{boundary}--\r\n").encode()
    return send(i.base, "POST", "/platform/proto/setproto/v1", token=token, body=data,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, timeout=20).status


def _localhost_bypass(i: Instance) -> int:
    token = _token(i)
    _call(i, "PUT", "/platform/security/settings", {"ip_whitelist": ["203.0.113.10"]}, token)
    return send(i.base, "GET", "/platform/user/me", token=token).status


def _autosave(i: Instance) -> bool:
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if any(path.suffix == ".bin" for path in i.workdir.rglob("*")):
            return True
        time.sleep(0.25)
    return False


def _token_without(i: Instance, claim: str) -> int:
    """Present a correctly signed admin token that lacks one claim."""
    token = _token(i)
    claims = {key: value for key, value in _claims(token).items() if key != claim}
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==="))
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=")
    signing_input = encode(header) + b"." + encode(claims)
    signature = base64.urlsafe_b64encode(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=")
    return send(i.base, "GET", "/platform/user/me", token=(signing_input + b"." + signature).decode()).status


def _discovery(i: Instance, ctx: Context) -> int:
    """Fetch a server-relative WSDL from the local fixture (subject to the discovery allow-list)."""
    _fixture(ctx)
    token = _token(i)
    _call(i, "POST", "/platform/api", {
        "api_name": "setdisc", "api_version": "v1", "api_description": "settings discovery probe",
        "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": [ctx.rest_upstream],
        "api_type": "REST", "api_allowed_retry_count": 0, "api_wsdl_url": "/wsdl"}, token)
    return send(i.base, "GET", "/platform/api/setdisc/v1/wsdl", token=token).status


def _metrics_saved(i: Instance) -> bool:
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if any(path.name == "metrics.json" for path in i.workdir.rglob("*")):
            return True
        time.sleep(0.25)
    return False


PROBES: dict[str, Callable[[Instance, Context], Any]] = {
    "preflight": lambda i, c: _preflight(i),
    "preflight_foreign": lambda i, c: _preflight(i, origin="https://foreign.invalid"),
    "preflight_header": lambda i, c: _preflight(i, headers="X-Custom-Probe"),
    "token_ttl": lambda i, c: _ttl_minutes(_token(i)),
    "login_cookies": lambda i, c: _cookie_attributes(_login(i)),
    "login": lambda i, c: _login(i).status,
    "authed": lambda i, c: send(i.base, "GET", "/platform/user/me", token=_token(i)).status,
    "large_auth": lambda i, c: send(i.base, "POST", "/platform/authorization", body=b'{"pad":"' + b"a" * 4096 + b'"}',
                                    headers={"Content-Type": "application/json"}).status,
    "large_api": lambda i, c: send(i.base, "POST", "/platform/api", token=_token(i),
                                   body=b'{"pad":"' + b"a" * 4096 + b'"}', headers={"Content-Type": "application/json"}).status,
    "page_size": lambda i, c: send(i.base, "GET", "/platform/role/all?page_size=5", token=_token(i)).status,
    "options": lambda i, c: send(i.base, "OPTIONS", "/platform/api/all").status,
    "memory_dump": lambda i, c: send(i.base, "POST", "/platform/memory/dump", token=_token(i), body=b"{}",
                                     headers={"Content-Type": "application/json"}).status,
    "vault": lambda i, c: _call(i, "POST", "/platform/vault", {"key_name": "settingprobe", "value": "v",
                                                              "description": "d"}).status,
    "breaker": lambda i, c: _gateway(i, c, faults={"statuses": [500] * 6}, calls=6),
    "slow_upstream": lambda i, c: _gateway(i, c, faults={"latency_ms": 2500}),
    "unroutable": lambda i, c: _gateway(i, c, servers=["http://10.255.255.1:81"])["statuses"],
    "retry": lambda i, c: _gateway(i, c, faults={"statuses": [503, 503]}, retry=2),
    "rest_body": lambda i, c: _gateway(i, c, method="POST", body=b'{"pad":"' + b"a" * 1024 + b'"}')["statuses"],
    "unsubscribed": lambda i, c: _gateway(i, c, subscribe=False)["statuses"],
    "proto_size": lambda i, c: _proto_upload(i, 400),
    "localhost_bypass": _localhost_bypass,
    "autosave": lambda i, c: _autosave(i),
    "openapi_discovery": lambda i, c: _call(i, "POST", "/platform/openapi/parse",
                                            {"url": c.rest_upstream + "/openapi.json"}).status,
    "discovery": _discovery,
    "no_aud": lambda i, c: _token_without(i, "aud"),
    "no_iss": lambda i, c: _token_without(i, "iss"),
    "metrics_saved": lambda i, c: _metrics_saved(i),
    "health": lambda i, c: send(i.base, "GET", "/platform/monitor/liveness").status,
}


@dataclass
class Setting:
    name: str
    positive: str
    invalid: str
    probe: str
    extra: dict[str, str] = field(default_factory=dict)
    # Documented candidate observations for settings the oracle does not read.
    expect: dict[str, Any] | None = None


KEYSET = json.dumps({"keys": [{"kid": "settings-k1", "algorithm": "HS256", "secret": JWT_SECRET + "-k1", "active": True}]})
SPEC: list[Setting] = [
    Setting("ALLOWED_ORIGINS", "https://system-e2e.invalid,https://other.invalid", "::not-a-url::", "preflight"),
    Setting("ALLOW_CREDENTIALS", "false", "sometimes", "preflight"),
    Setting("ALLOW_HEADERS", "Content-Type,X-Custom-Probe", "", "preflight_header"),
    Setting("ALLOW_METHODS", "GET,POST", "NOT A METHOD", "preflight"),
    Setting("AUTH_EXPIRE_TIME", "5", "-3", "token_ttl"),
    Setting("AUTH_EXPIRE_TIME_FREQ", "hours", "fortnights", "token_ttl"),
    Setting("AUTH_REFRESH_EXPIRE_TIME", "2", "abc", "login_cookies"),
    Setting("AUTH_REFRESH_EXPIRE_FREQ", "hours", "bogus", "login_cookies"),
    Setting("BODY_LIMIT_EXCLUDE_PATHS", "/platform/authorization", ",,,", "large_auth", {"MAX_BODY_SIZE_BYTES": "1024"}),
    Setting("CIRCUIT_BREAKER_ENABLED", "false", "maybe", "breaker", {"CIRCUIT_BREAKER_THRESHOLD": "2"}),
    Setting("CIRCUIT_BREAKER_THRESHOLD", "2", "-1", "breaker"),
    Setting("CIRCUIT_BREAKER_TIMEOUT", "1", "x", "breaker", {"CIRCUIT_BREAKER_THRESHOLD": "2"}),
    Setting("COOKIE_DOMAIN", "example.test", "", "login_cookies"),
    Setting("COOKIE_SAMESITE", "Lax", "Sideways", "login_cookies"),
    Setting("COOKIE_SECURE", "true", "perhaps", "login_cookies"),
    Setting("CORS_STRICT", "false", "maybe", "preflight_foreign"),
    Setting("DISABLE_BODY_SIZE_LIMIT", "true", "maybe", "large_api", {"MAX_BODY_SIZE_BYTES": "1024"}),
    Setting("DISCOVERY_ALLOWED_HOSTS", "{upstream_host}", "", "discovery",
            expect={"positive": {"started": True, "probe": 200}, "invalid": {"started": True, "probe": 400}}),
    Setting("DOORMAN_ENABLE_GRPC_REFLECTION", "true", "maybe", "health"),
    Setting("ENFORCE_ADMIN_SUBSCRIPTION", "true", "maybe", "unsubscribed"),
    Setting("GATEWAY_TIMEOUT", "1", "abc", "slow_upstream"),
    Setting("GRPC_RETRY_BASE_MS", "5", "x", "health"),
    Setting("GRPC_RETRY_MAX_MS", "20", "x", "health"),
    Setting("HTTP_CONNECT_TIMEOUT", "0.5", "fast", "unroutable"),
    Setting("HTTP_READ_TIMEOUT", "1", "x", "slow_upstream"),
    Setting("HTTP_RETRY_BASE_DELAY", "0.01", "x", "retry"),
    Setting("HTTP_RETRY_MAX_DELAY", "0.05", "x", "retry"),
    Setting("JWT_AUDIENCE", "settings-audience", "", "no_aud",
            expect={"positive": {"started": True, "probe": 401}, "invalid": {"started": True, "probe": 401}}),
    Setting("JWT_ISSUER", "settings-issuer", "", "no_iss",
            expect={"positive": {"started": True, "probe": 401}, "invalid": {"started": True, "probe": 401}}),
    Setting("JWT_KEYS", KEYSET, "{not json", "authed"),
    Setting("JWT_SECRET_KEY", JWT_SECRET + "-alt", "", "authed"),
    Setting("LOCAL_HOST_IP_BYPASS", "true", "maybe", "localhost_bypass"),
    Setting("MAX_BODY_SIZE_BYTES", "2048", "-5", "large_api"),
    Setting("MAX_BODY_SIZE_BYTES_GRAPHQL", "512", "-5", "rest_body"),
    Setting("MAX_BODY_SIZE_BYTES_GRPC", "512", "-5", "rest_body"),
    Setting("MAX_BODY_SIZE_BYTES_REST", "512", "-5", "rest_body"),
    Setting("MAX_BODY_SIZE_BYTES_SOAP", "512", "-5", "rest_body"),
    Setting("MAX_PAGE_SIZE", "1", "zero", "page_size"),
    Setting("MAX_PROTO_SIZE_BYTES", "100", "x", "proto_size"),
    Setting("MEM_AUTO_SAVE_ENABLED", "true", "maybe", "autosave", {"MEM_AUTO_SAVE_FREQ": "1"}),
    Setting("MEM_AUTO_SAVE_FREQ", "1", "x", "autosave", {"MEM_AUTO_SAVE_ENABLED": "true"}),
    Setting("MEM_DUMP_PATH", "{workdir}/custom-dump.bin", "/proc/forbidden/dump.bin", "memory_dump"),
    Setting("MEM_ENCRYPTION_KEY", "settings-probe-key-0123456789abcd", "short", "memory_dump"),
    Setting("MEM_OR_EXTERNAL", "MEM", "BOGUS", "login"),
    Setting("METRICS_SAVE_INTERVAL", "1", "x", "metrics_saved",
            expect={"positive": {"started": True, "probe": True}, "invalid": {"started": True, "probe": False}}),
    Setting("RETRY_BACKOFF", "0.01", "x", "retry"),
    Setting("RETRY_ENABLED", "false", "maybe", "retry"),
    Setting("RETRY_MAX_ATTEMPTS", "1", "-2", "retry"),
    Setting("STRICT_OPTIONS_405", "true", "maybe", "options"),
    Setting("THREADS", "1", "4", "login"),
    Setting("VAULT_KEY", "settings-vault-key-0123456789abcdef", "", "vault"),
]


@dataclass
class SettingOutcome:
    scenario_id: str
    passed: bool
    observation: dict[str, Any]
    reason: str = ""


def observe(launcher: Launcher, ctx: Context, implementation: str, env: dict[str, str], probe: str) -> dict[str, Any]:
    instance = launcher.start(implementation, env)
    if instance is None:
        return {"started": False}
    try:
        return {"started": True, "probe": PROBES[probe](instance, ctx)}
    except Exception as error:  # noqa: BLE001 -- a probe failure is an observation
        return {"started": True, "probe_error": type(error).__name__}
    finally:
        launcher.stop(instance)


def run_setting(launcher: Launcher, ctx: Context, setting: Setting, kind: str) -> SettingOutcome:
    scenario_id = f"setting::{setting.name}::{kind}"
    host = urllib.parse.urlsplit(ctx.rest_upstream).hostname or ""
    env = {key: value.replace("{upstream_host}", host) for key, value in
           {**setting.extra, setting.name: setting.positive if kind == "positive" else setting.invalid}.items()}
    candidate = observe(launcher, ctx, "rust", env, setting.probe)
    if setting.name in RUST_ONLY:
        expected = (setting.expect or {}).get(kind)
        passed = expected is not None and candidate == expected
        return SettingOutcome(scenario_id, passed, {"candidate": candidate, "expected": expected},
                              "" if passed else "candidate does not match the documented expectation")
    oracle = observe(launcher, ctx, "python", env, setting.probe)
    observation = {"candidate": candidate, "oracle": oracle}
    if candidate == oracle:
        return SettingOutcome(scenario_id, True, observation)
    approved = next((a for a in load_approvals() if a.covers(scenario_id, observation)), None)
    if approved:
        return SettingOutcome(scenario_id, True, observation, f"approved: {approved.rationale}")
    return SettingOutcome(scenario_id, False, observation, "setting behaviour differs from pinned oracle")


# --------------------------------------------------------------------------- native launcher


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class NativeLauncher:
    """Starts the Rust binary and the pinned Python checkout as local processes."""

    def __init__(self, rust_binary: Path, python_dir: Path, python: Path):
        self.rust_binary, self.python_dir, self.python = rust_binary, python_dir, python

    def start(self, implementation: str, env: dict[str, str]) -> Instance | None:
        workdir = Path(tempfile.mkdtemp(prefix=f"doorman-setting-{implementation}-"))
        port = free_port()
        values = {**BASE_ENV, "PORT": str(port), "MEM_DUMP_PATH": str(workdir / "dump.bin"),
                  "SECURITY_SETTINGS_FILE": str(workdir / "security_settings.json"), "LOGS_DIR": str(workdir / "logs")}
        values.update({key: value.replace("{workdir}", str(workdir)) for key, value in env.items()})
        environment = {key: value for key, value in os.environ.items() if key not in values}
        environment.update(values)
        if implementation == "python":
            command, cwd = [str(self.python), "doorman.py", "run"], self.python_dir
        else:
            command, cwd = [str(self.rust_binary)], workdir
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=(workdir / "out.log").open("w"),
                                   stderr=subprocess.STDOUT, start_new_session=True)
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                shutil.rmtree(workdir, ignore_errors=True)
                return None
            if send(base, "GET", "/platform/monitor/liveness", timeout=2).status == 200:
                return Instance(base, workdir, process)
            time.sleep(0.3)
        self.stop(Instance(base, workdir, process))
        return None

    def stop(self, instance: Instance) -> None:
        process: subprocess.Popen[bytes] = instance.handle
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        shutil.rmtree(instance.workdir, ignore_errors=True)


class DockerLauncher:
    """Starts the candidate and pinned oracle images on the system E2E network.

    Each instance gets a host work directory mounted at /work for dumps, logs
    and security settings, so file-based probes read the same paths as the
    native launcher.
    """

    PORTS = {"rust": 3001, "python": 8000}

    def __init__(self, images: dict[str, str], network: str, labels: dict[str, str], prefix: str):
        self.images, self.network, self.labels, self.prefix = images, network, labels, prefix
        self.counter = 0

    def start(self, implementation: str, env: dict[str, str]) -> Instance | None:
        self.counter += 1
        workdir = Path(tempfile.mkdtemp(prefix=f"doorman-setting-{implementation}-"))
        workdir.chmod(0o777)
        port = free_port()
        name = f"{self.prefix}-setting-{implementation}-{self.counter}"
        values = {**BASE_ENV, "HOST": "0.0.0.0", "PORT": str(self.PORTS[implementation]),
                  "WEB_HOST": "0.0.0.0", "WEB_PORT": "3000", "MEM_DUMP_PATH": "/work/dump.bin",
                  "SECURITY_SETTINGS_FILE": "/work/security_settings.json", "LOGS_DIR": "/work/logs"}
        values.update({key: value.replace("{workdir}", "/work") for key, value in env.items()})
        env_file = Path(tempfile.mkdtemp(prefix="doorman-setting-env-")) / "system.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
        env_file.chmod(0o644)
        command = ["docker", "run", "--detach", "--name", name, "--network", self.network,
                   "--publish", f"127.0.0.1:{port}:{self.PORTS[implementation]}",
                   "--mount", f"type=bind,src={workdir},dst=/work"]
        for key, value in self.labels.items():
            command += ["--label", f"{key}={value}"]
        if implementation == "rust":
            command += ["--mount", f"type=bind,src={env_file},dst=/env/system.env,readonly"]
        else:
            command += ["--env-file", str(env_file)]
        started = subprocess.run([*command, self.images[implementation]], capture_output=True, text=True)
        if implementation == "python":
            # --env-file is read at creation; the bind-mounted candidate file must stay.
            shutil.rmtree(env_file.parent, ignore_errors=True)
        instance = Instance(f"http://127.0.0.1:{port}", workdir, (name, env_file))
        if started.returncode != 0:
            self.stop(instance)
            return None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                                   capture_output=True, text=True).stdout.strip()
            if state != "true":
                self.stop(instance)
                return None
            if send(instance.base, "GET", "/platform/monitor/liveness", timeout=2).status == 200:
                return instance
            time.sleep(0.5)
        self.stop(instance)
        return None

    def stop(self, instance: Instance) -> None:
        name, env_file = instance.handle
        subprocess.run(["docker", "rm", "--force", name], capture_output=True)
        shutil.rmtree(env_file.parent, ignore_errors=True)
        # Files written by the container user may not be removable here.
        subprocess.run(["docker", "run", "--rm", "--mount", f"type=bind,src={instance.workdir},dst=/work",
                        "--entrypoint", "sh", self.images["rust"], "-c", "rm -rf /work/* /work/.[!.]*"],
                       capture_output=True)
        shutil.rmtree(instance.workdir, ignore_errors=True)


def run_corpus(launcher: Launcher, ctx: Context, pattern: str = "") -> list[SettingOutcome]:
    outcomes = []
    for setting in SPEC:
        for kind in ("positive", "invalid"):
            if pattern and not re.search(pattern, f"{setting.name}::{kind}"):
                continue
            outcomes.append(run_setting(launcher, ctx, setting, kind))
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-binary", type=Path, required=True)
    parser.add_argument("--python-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--rest-upstream", required=True)
    parser.add_argument("--filter", default="")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    launcher = NativeLauncher(args.rust_binary.resolve(), args.python_dir.resolve(), args.python.absolute())
    ctx = Context(args.rest_upstream, args.rest_upstream)
    outcomes = []
    for setting in SPEC:
        for kind in ("positive", "invalid"):
            if args.filter and not re.search(args.filter, f"{setting.name}::{kind}"):
                continue
            outcome = run_setting(launcher, ctx, setting, kind)
            outcomes.append(outcome)
            print(("PASS " if outcome.passed else "FAIL ") + outcome.scenario_id + " " +
                  json.dumps(outcome.observation, sort_keys=True), flush=True)
    failed = sum(not o.passed for o in outcomes)
    print(f"setting scenarios={len(outcomes)} passed={len(outcomes) - failed} failed={failed}")
    if args.report:
        args.report.write_text(json.dumps([o.__dict__ for o in outcomes], indent=1) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
