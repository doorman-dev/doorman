#!/usr/bin/env python3
"""Differential operation executor for the comprehensive system E2E corpus.

Every executable `openapi-operation` cell (frozen operation x request class) is
run against the candidate and the pinned Python oracle after both have been
seeded with an identical world.  The Python response is the expectation for
status, media type, allowed methods, and body class; candidate-only invariants
cover redaction and security headers, and a state digest after every accepted
mutation proves both stores still agree.  A difference passes only when it is
listed in system-tests/approvals.json with a rationale.
"""

from __future__ import annotations

import argparse
import base64
import copy
import gzip
import hashlib
import hmac
import http.client
import json
import re
import select
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.differential_parity import load_openapi, resolve_local_ref  # noqa: E402

OPENAPI = ROOT / "parity/openapi/python-openapi.json.gz.b64"
SYSTEM = ROOT / "system-tests"
OVERSIZED_BYTES = 12 * 1024 * 1024
WORLD_PASSWORD = "SystemWorld!Pass2026"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
# Names the builder gives scenario-owned entities (fresh creates and disposables).
SCENARIO_NAME = re.compile(r"sys[nd]\d{5}")
SECURITY_HEADERS = ("x-content-type-options", "x-frame-options")


# --------------------------------------------------------------------------- HTTP


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def decoded_body(self) -> bytes:
        if self.headers.get("content-encoding", "").lower() == "gzip":
            try:
                return gzip.decompress(self.body)
            except (OSError, EOFError):
                pass
        return self.body

    def json(self) -> Any:
        try:
            body = self.decoded_body()
            return json.loads(body) if body else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def signature(self) -> dict[str, Any]:
        media = self.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        allow = sorted(t.strip().upper() for t in self.headers.get("allow", "").split(",") if t.strip())
        value = self.json()
        error_code = value.get("error_code") if isinstance(value, dict) else None
        keys = sorted(value) if isinstance(value, dict) else None
        return {
            "status": self.status, "content_type": media,
            "content_encoding": self.headers.get("content-encoding", "").lower(), "allow": allow,
            "body_class": body_class(self), "error_code": error_code, "keys": keys,
        }


def body_class(response: Response) -> str:
    if not response.body:
        return "empty"
    value = response.json()
    if isinstance(value, dict):
        if "error_code" in value or "detail" in value or "error_message" in value:
            return "error"
        return "object"
    if isinstance(value, list):
        return "array"
    if value is not None:
        return "scalar"
    return "text"


def send(
    base: str,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30,
) -> Response:
    outgoing = {"Accept": "application/json", **(headers or {})}
    if token:
        outgoing["Authorization"] = f"Bearer {token}"
    if body and len(body) > 1024 * 1024 and base.startswith("http://"):
        return send_large_body(base, method, path, body, outgoing, timeout)
    request = urllib.request.Request(base + path, data=body, headers=outgoing, method=method)
    try:
        raw = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        raw = error
    except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
        return Response(599, {}, str(error).encode())
    with raw:
        data = raw.read()
        return Response(raw.status, {k.lower(): v for k, v in raw.headers.items()}, data)


def send_large_body(base: str, method: str, path: str, body: bytes, headers: dict[str, str],
                    timeout: float) -> Response:
    """Read an early 413 before the server closes an unfinished upload."""
    parts = urllib.parse.urlsplit(base)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        connection.putrequest(method, path)
        for name, value in {**headers, "Content-Length": str(len(body))}.items():
            connection.putheader(name, value)
        connection.endheaders()
        sock = connection.sock
        if sock is None:
            raise ConnectionError("upload socket did not open")
        sock.setblocking(False)
        remaining = memoryview(body)
        deadline = time.monotonic() + timeout
        while remaining:
            wait = deadline - time.monotonic()
            if wait <= 0:
                raise TimeoutError("upload timed out")
            readable, writable, _ = select.select([sock], [sock], [], wait)
            if readable:
                break
            if writable:
                try:
                    sent = sock.send(remaining[:65536])
                except BlockingIOError:
                    continue
                except (BrokenPipeError, ConnectionResetError):
                    break
                if sent == 0:
                    break
                remaining = remaining[sent:]
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        reply = connection.getresponse()
        return Response(reply.status, {k.lower(): v for k, v in reply.getheaders()}, reply.read())
    except (OSError, http.client.HTTPException) as error:
        return Response(599, {}, str(error).encode())
    finally:
        connection.close()


def json_body(value: Any) -> tuple[bytes, dict[str, str]]:
    return json.dumps(value, separators=(",", ":")).encode(), {"Content-Type": "application/json"}


# --------------------------------------------------------------------------- JWT


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def remint(token: str, secret: str, **changes: Any) -> str:
    """Re-sign a server-issued HS256 token with modified claims."""
    header_text, payload_text, _ = token.split(".")
    payload = json.loads(_unb64(payload_text))
    for key, value in changes.items():
        if value is None:
            payload.pop(key, None)
        else:
            payload[key] = value
    signing_input = f"{header_text}.{_b64(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


# --------------------------------------------------------------------------- targets / world


@dataclass
class Target:
    name: str
    base: str
    admin_email: str
    admin_password: str
    jwt_secret: str
    tokens: dict[str, str] = field(default_factory=dict)
    ids: dict[str, str] = field(default_factory=dict)
    # Two-node topology: a second node sharing storage that serves cross_node requests.
    peer: str | None = None

    def login(self, email: str, password: str) -> str:
        body, headers = json_body({"email": email, "password": password})
        response = send(self.base, "POST", "/platform/authorization", body=body, headers=headers)
        value = response.json()
        while isinstance(value, dict) and isinstance(value.get("response"), dict):
            value = value["response"]
        token = value.get("access_token") if isinstance(value, dict) else None
        if response.status != 200 or not isinstance(token, str):
            raise RuntimeError(f"{self.name}: login for {email} failed with HTTP {response.status}")
        return token

    def call(self, method: str, path: str, value: Any = None, *, token: str | None = None) -> Response:
        body, headers = (json_body(value) if value is not None else (None, {}))
        response = send(self.base, method, path, token=token or self.tokens["admin"], body=body, headers=headers)
        # A scenario (e.g. self-invalidation) may have ended the admin session;
        # the pinned server reports that as 500 on routes that swallow the 401.
        if response.status in (401, 500) and token is None:
            self.tokens["admin"] = self.login(self.admin_email, self.admin_password)
            response = send(self.base, method, path, token=self.tokens["admin"], body=body, headers=headers)
        return response


# Both servers enforce a user limit whenever its count is set (the seeded admin
# allows 1 request/second), whatever the *_enabled flag says, so raise the counts.
UNLIMITED = {"rate_limit_enabled": False, "throttle_enabled": False, "bandwidth_limit_enabled": False,
             "rate_limit_duration": 1000000, "rate_limit_duration_type": "second",
             "throttle_duration": 1000000, "throttle_duration_type": "second", "throttle_queue_limit": 1000000}
FULL_ROLE = {
    "role_description": "system e2e full access",
    **{
        name: True
        for name in (
            "manage_users", "manage_apis", "manage_endpoints", "manage_groups", "manage_roles",
            "manage_routings", "manage_gateway", "manage_subscriptions", "manage_credits",
            "manage_auth", "manage_security", "manage_tiers", "manage_rate_limits",
            "view_analytics", "view_logs", "export_logs", "ui_access",
        )
    },
}
PRINCIPALS = {
    # principal: (role, groups, active)
    "sysuser": ("sysrole", ["sysgroup"], True),
    "sysadmin": ("sysfull", ["ALL", "sysgroup"], True),
    "sysrevoke": ("sysfull", ["ALL"], True),
    "sysinval": ("sysfull", ["ALL"], True),
    "sysdisabled": ("sysfull", ["ALL"], True),
}


FIXTURE_PROTO = ('syntax = "proto3"; package fixture.v1; service Resource { rpc Create (Request) '
                 'returns (Reply); } message Request { string name = 1; } message Reply { string message = 1; }')
# (api_name, api_type, upstream key, endpoint method, endpoint uri)
PROTOCOL_APIS = (
    ("syssoap", "SOAP", "soap", "POST", "/soap"),
    ("sysgql", "GRAPHQL", "graphql", "POST", "/graphql"),
    ("sysgrpc", "GRPC", "grpc", "POST", "/grpc"),
)
# Gateway operations carry protocol payloads the OpenAPI document does not model.
GATEWAY_BASELINES = {
    "/api/rest/{path}": ("sysapi/v1/items", None, {}),
    "/api/soap/{path}": ("syssoap/v1/soap",
                         b'<?xml version="1.0"?><Envelope><Body><Ping/></Body></Envelope>',
                         {"Content-Type": "text/xml"}),
    "/api/graphql/{path}": ("sysgql", b'{"query":"{ hello }"}',
                            {"Content-Type": "application/json", "X-API-Version": "v1"}),
    "/api/grpc/{path}": ("sysgrpc", b'{"method":"Resource.Create","message":{"name":"probe"}}',
                         {"Content-Type": "application/json", "X-API-Version": "v1"}),
}


WORLD_NAMES = {
    "sysapi", *(name for name, *_ in PROTOCOL_APIS), "ALL", "admin", "sysgroup", "sysfull", "sysrole",
    "sysclient", *PRINCIPALS,
}


class World:
    """Identical, idempotently restorable state on every target."""

    def __init__(self, rest_upstream: str, upstreams: dict[str, str] | None = None):
        self.rest_upstream = rest_upstream.rstrip("/")
        # protocol -> upstream base (soap/graphql over http, grpc as grpc://host:port)
        self.upstreams = {key: value.rstrip("/") for key, value in (upstreams or {}).items()}

    def api(self) -> dict[str, Any]:
        return {
            "api_name": "sysapi", "api_version": "v1", "api_description": "system e2e world",
            "api_allowed_roles": ["admin", "sysfull"], "api_allowed_groups": ["ALL"],
            "api_servers": [self.rest_upstream], "api_type": "REST", "api_allowed_retry_count": 0,
            "active": True,
        }

    def ensure(self, target: Target) -> None:
        call = target.call

        def exists(path: str) -> bool:
            # Look before creating: the pinned server's duplicate checks read a
            # cache that a scenario may have flushed.
            return call("GET", path).status == 200

        for role, payload in (
            ("sysrole", {"role_name": "sysrole", "role_description": "system e2e no permissions"}),
            ("sysfull", {"role_name": "sysfull", **FULL_ROLE}),
        ):
            if exists(f"/platform/role/{role}") or call("POST", "/platform/role", payload).status not in (200, 201):
                call("PUT", f"/platform/role/{role}", {k: v for k, v in payload.items() if k != "role_name"})
        group = {"group_name": "sysgroup", "group_description": "system e2e", "api_access": []}
        if exists("/platform/group/sysgroup") or call("POST", "/platform/group", group).status not in (200, 201):
            call("PUT", "/platform/group/sysgroup", {"group_description": "system e2e"})
        for username, (role, groups, active) in PRINCIPALS.items():
            user = {
                "username": username, "email": f"{username}@example.test", "password": WORLD_PASSWORD,
                "role": role, "groups": groups, "active": active, "ui_access": True,
            }
            if exists(f"/platform/user/{username}") or call("POST", "/platform/user", user).status not in (200, 201):
                call("PUT", f"/platform/user/{username}", {"role": role, "groups": groups, "active": active})
        # Per-user traffic limits would trip at slightly different moments on the
        # two servers under corpus volume; the limit behaviour itself is covered
        # by the higher-order and pairwise packs.
        # The bootstrap admin accepts only operational limit fields (USR020).
        call("PUT", "/platform/user/admin", {k: v for k, v in UNLIMITED.items() if k != "bandwidth_limit_enabled"})
        for username in PRINCIPALS:
            call("PUT", f"/platform/user/{username}", UNLIMITED)
        if call("POST", "/platform/api", self.api()).status not in (200, 201):
            update = {k: v for k, v in self.api().items() if k not in ("api_name", "api_version")}
            call("PUT", "/platform/api/sysapi/v1", update)
        endpoint = {
            "api_name": "sysapi", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/items", "endpoint_description": "system e2e items",
        }
        call("POST", "/platform/endpoint", endpoint)
        for name, kind, key, method, uri in PROTOCOL_APIS:
            upstream = self.upstreams.get(key)
            if not upstream:
                continue
            api = {**self.api(), "api_name": name, "api_type": kind, "api_servers": [upstream]}
            if kind == "GRPC":
                # No package override: the pinned server only resolves protos
                # compiled under the default <api>_<version> module base.
                api["api_grpc_web_enabled"] = True
            if call("POST", "/platform/api", api).status not in (200, 201):
                call("PUT", f"/platform/api/{name}/v1",
                     {k: v for k, v in api.items() if k not in ("api_name", "api_version")})
            call("POST", "/platform/endpoint", {
                "api_name": name, "api_version": "v1", "endpoint_method": method,
                "endpoint_uri": uri, "endpoint_description": f"system e2e {key}"})
            if kind == "GRPC":
                boundary = "----system-e2e-world"
                data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.proto\"\r\n"
                        f"Content-Type: application/octet-stream\r\n\r\n{FIXTURE_PROTO}\r\n--{boundary}--\r\n").encode()
                send(target.base, "POST", f"/platform/proto/{name}/v1", token=target.tokens["admin"], body=data,
                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
            for principal in ("admin", "sysadmin"):
                call("POST", "/platform/subscription/subscribe",
                     {"username": principal, "api_name": name, "api_version": "v1"})
        found = call("GET", "/platform/endpoint/GET/sysapi/v1/items").json()
        while isinstance(found, dict) and isinstance(found.get("response"), dict):
            found = found["response"]
        if isinstance(found, dict) and found.get("endpoint_id"):
            target.ids["endpoint_id"] = str(found["endpoint_id"])
        call("POST", "/platform/subscription/subscribe",
             {"username": "admin", "api_name": "sysapi", "api_version": "v1"})
        call("POST", "/platform/subscription/subscribe",
             {"username": "sysadmin", "api_name": "sysapi", "api_version": "v1"})
        routing = {"client_key": "sysclient", "routing_name": "system e2e",
                   "routing_servers": [self.rest_upstream], "routing_description": "system e2e"}
        if exists("/platform/routing/sysclient") or call("POST", "/platform/routing", routing).status not in (200, 201):
            call("PUT", "/platform/routing/sysclient", {"routing_servers": [self.rest_upstream]})
        credit = {"api_credit_group": "syscredit", "api_key": "sys-credit-secret-key-0001",
                  "api_key_header": "x-api-key",
                  "credit_tiers": [{"tier_name": "basic", "credits": 100, "input_limit": 0,
                                    "output_limit": 0, "reset_frequency": "monthly"}]}
        if call("POST", "/platform/credit", credit).status not in (200, 201):
            call("PUT", "/platform/credit/syscredit", credit)
        vault = {"key_name": "syskey", "value": "sys-vault-secret-value-0001", "description": "system e2e"}
        if call("POST", "/platform/vault", vault).status not in (200, 201):
            call("PUT", "/platform/vault/syskey", {"value": vault["value"]})
        # The pinned TierName enum admits only free/pro/enterprise/custom.
        tier = {"tier_id": "systier", "name": "custom", "display_name": "System",
                "limits": {"requests_per_minute": 1000000000}}
        if call("POST", "/platform/tiers/", tier).status not in (200, 201):
            call("PUT", "/platform/tiers/systier", {"display_name": "System", "enabled": True})
        rule = {"rule_id": "sysrule", "rule_type": "per_user", "target_identifier": "sysuser",
                "time_window": "minute", "limit": 1000000000, "enabled": True}
        if call("POST", "/platform/rate-limits/", rule).status not in (200, 201):
            call("PUT", "/platform/rate-limits/sysrule", {"limit": 1000000000, "enabled": True})

    def refresh_tokens(self, target: Target) -> None:
        target.tokens["admin"] = target.login(target.admin_email, target.admin_password)
        for username in PRINCIPALS:
            target.tokens[username] = self.principal_login(target, username)

    @staticmethod
    def principal_login(target: Target, username: str) -> str:
        """Log a principal in, restoring its password if a scenario changed it."""
        try:
            return target.login(f"{username}@example.test", WORLD_PASSWORD)
        except RuntimeError:
            target.call("PUT", f"/platform/user/{username}/update-password", {"new_password": WORLD_PASSWORD})
            return target.login(f"{username}@example.test", WORLD_PASSWORD)

    def digest(self, target: Target) -> dict[str, Any]:
        """Order-insensitive identity of the durable collections the world uses."""
        result: dict[str, Any] = {}
        for name, path, key in (
            ("apis", "/platform/api/all?page_size=200", "api_name"),
            ("roles", "/platform/role/all?page_size=200", "role_name"),
            ("groups", "/platform/group/all?page_size=200", "group_name"),
            ("users", "/platform/user/all?page_size=200", "username"),
            ("routings", "/platform/routing/all?page_size=200", "client_key"),
        ):
            value = target.call("GET", path).json()
            while isinstance(value, dict) and not isinstance(value.get(name), list) and isinstance(value.get("response"), (dict, list)):
                value = value["response"]
            items = value.get(name) if isinstance(value, dict) else value
            # Names are compared as a set: after a cache flush the pinned server's
            # cache-based duplicate checks let a repeated create insert a second
            # record with the same name (a Python bug the candidate does not share).
            # Only the world and scenario-owned entities are tracked: the demo
            # seeder, for one, creates randomly named records on each server.
            result[name] = sorted({
                str(item.get(key)) for item in items or []
                if isinstance(item, dict) and (str(item.get(key)) in WORLD_NAMES or SCENARIO_NAME.fullmatch(str(item.get(key))))
            })
        return result


# --------------------------------------------------------------------------- request synthesis


PATH_VALUES = {
    "api_name": "sysapi", "api_version": "v1", "version": "v1", "username": "sysuser",
    "user_id": "sysuser", "group_name": "sysgroup", "role_name": "sysrole",
    "client_key": "sysclient", "api_credit_group": "syscredit", "key_name": "syskey",
    "tier_id": "systier", "rule_id": "sysrule", "endpoint_method": "GET",
    "endpoint_uri": "items", "email": "sysuser@example.test", "path": "sysapi/v1/items",
    "service": "fixture.v1.Resource", "method": "Create",
}
FIELD_VALUES = {
    "api_name": "sysapi", "api_version": "v1", "username": "sysuser",
    "email": "sysuser@example.test", "role": "sysrole", "group_name": "sysgroup",
    "role_name": "sysrole", "client_key": "sysclient", "api_credit_group": "syscredit",
    "key_name": "syskey", "tier_id": "systier", "rule_id": "sysrule", "user_id": "sysuser",
    "endpoint_method": "GET", "endpoint_uri": "/items", "groups": ["sysgroup"],
    "password": WORLD_PASSWORD, "new_password": WORLD_PASSWORD + "x", "old_password": WORLD_PASSWORD,
    "rule_ids": ["sysrule"], "backend": "redis", "enabled": False, "duration_ms": 0,
    "origin": "https://system-e2e.invalid", "method": "GET",
}
# Collection creates get a fresh, deterministic identity per scenario so the
# success class exercises creation rather than colliding with the seeded world.
CREATE_KEYS = {
    "/platform/api": ("api_name",), "/platform/user": ("username", "email"),
    "/platform/group": ("group_name",), "/platform/role": ("role_name",),
    "/platform/routing": ("client_key",), "/platform/credit": ("api_credit_group",),
    "/platform/vault": ("key_name",), "/platform/tiers": ("tier_id", "name"),
    "/platform/rate-limits": ("rule_id",),
}


class Synthesizer:
    def __init__(self, document: dict[str, Any], world: World):
        self.document = document
        self.world = world

    def schema(self, value: Any) -> dict[str, Any]:
        value = resolve_local_ref(self.document, value or {})
        if "allOf" in value and len(value["allOf"]) == 1:
            merged = {**resolve_local_ref(self.document, value["allOf"][0]), **{k: v for k, v in value.items() if k != "allOf"}}
            return merged
        return value

    def value(self, name: str, schema: Any, depth: int = 0) -> Any:
        schema = self.schema(schema)
        if name in FIELD_VALUES:
            return copy.deepcopy(FIELD_VALUES[name])
        if name == "api_servers":
            return [self.world.rest_upstream]
        if "example" in schema:
            return copy.deepcopy(schema["example"])
        if "default" in schema:
            return copy.deepcopy(schema["default"])
        if schema.get("enum"):
            return schema["enum"][0]
        kind = schema.get("type")
        if kind == "object" or "properties" in schema:
            return self.object(schema, depth + 1) if depth < 4 else {}
        if kind == "array":
            return [self.value(name, schema.get("items", {}), depth + 1)] if depth < 4 else []
        if kind == "integer":
            return max(int(schema.get("minimum", 1)), 1)
        if kind == "number":
            return 1.0
        if kind == "boolean":
            return True
        text = "sysvalue"
        return text.ljust(int(schema.get("minLength", 0)), "x")[: int(schema.get("maxLength", 64))]

    def object(self, schema: Any, depth: int = 0) -> dict[str, Any]:
        schema = self.schema(schema)
        required = set(schema.get("required", []))
        return {
            name: self.value(name, prop, depth)
            for name, prop in schema.get("properties", {}).items()
            if name in required
        }


@dataclass
class Operation:
    method: str
    path: str
    parameters: list[dict[str, Any]]
    body_schema: dict[str, Any] | None
    media: str | None


@dataclass
class Prepared:
    method: str
    path: str
    body: bytes | None
    headers: dict[str, str]
    token_key: str | None = "admin"
    raw_token: str | None = None
    cross_node: bool = False
    prelude: list[tuple[str, str, Any]] = field(default_factory=list)
    repeat: int = 1


def operations(document: dict[str, Any]) -> dict[tuple[str, str], Operation]:
    result: dict[tuple[str, str], Operation] = {}
    for path, item in document["paths"].items():
        item = resolve_local_ref(document, item)
        for method, op in item.items():
            if method not in ("get", "post", "put", "patch", "delete", "head", "options", "trace"):
                continue
            op = resolve_local_ref(document, op)
            parameters = [
                resolve_local_ref(document, p)
                for p in [*(item.get("parameters") or []), *(op.get("parameters") or [])]
            ]
            body_schema = media = None
            request_body = resolve_local_ref(document, op.get("requestBody") or {})
            for media_type, content in (request_body.get("content") or {}).items():
                media, body_schema = media_type, content.get("schema") or {}
                break
            result[(method.upper(), path)] = Operation(method.upper(), path, parameters, body_schema, media)
    return result


# --------------------------------------------------------------------------- classes


class Builder:
    def __init__(self, synth: Synthesizer):
        self.synth = synth
        self.counter = 0

    def render_path(self, op: Operation, target: Target, overrides: dict[str, str] | None = None) -> str:
        path = op.path
        query: list[tuple[str, str]] = []
        for parameter in op.parameters:
            name = str(parameter.get("name"))
            if parameter.get("in") == "path":
                gateway = GATEWAY_BASELINES.get(op.path)
                default = gateway[0] if gateway and name == "path" else PATH_VALUES.get(name, "sysvalue")
                if op.path.startswith("/grpc-web/") and name == "api_name":
                    default = "sysgrpc"
                value = (overrides or {}).get(name) or target.ids.get(name) or default
                path = path.replace("{" + name + "}", urllib.parse.quote(value, safe="/" if name == "path" else ""))
                path = path.replace("{" + name + ":path}", value)
            elif parameter.get("in") == "query" and parameter.get("required"):
                query.append((name, str(self.synth.value(name, parameter.get("schema", {})))))
        if op.path == "/platform/demo/seed":
            # Keep the seeded world small; defaults create dozens of entities.
            query += [("users", "1"), ("apis", "1"), ("endpoints", "1"), ("groups", "1"),
                      ("protos", "0"), ("logs", "1"), ("seed", "7")]
        if query:
            path += "?" + urllib.parse.urlencode(query)
        return path

    def body(self, op: Operation, fresh: str | None) -> tuple[bytes | None, dict[str, str], Any]:
        gateway = GATEWAY_BASELINES.get(op.path)
        if gateway and op.method not in ("GET", "HEAD", "DELETE"):
            return gateway[1], dict(gateway[2]), None
        if gateway:
            return None, {k: v for k, v in gateway[2].items() if k != "Content-Type"}, None
        if op.path.startswith("/grpc-web/"):
            return b"\x00\x00\x00\x00\x00", {"Content-Type": "application/grpc-web+proto"}, None
        if not op.body_schema:
            return None, {}, None
        if op.media and op.media.startswith("multipart/"):
            boundary = "----system-e2e-boundary"
            proto = ('syntax = "proto3"; package fixture.v1; service Resource { rpc Create (Request) '
                     'returns (Reply); } message Request { string name = 1; } message Reply { string message = 1; }')
            data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sys.proto\"\r\n"
                    f"Content-Type: application/octet-stream\r\n\r\n{proto}\r\n--{boundary}--\r\n").encode()
            return data, {"Content-Type": f"multipart/form-data; boundary={boundary}"}, None
        value = self.synth.object(op.body_schema) if self.synth.schema(op.body_schema).get("properties") else self.synth.value("body", op.body_schema)
        if fresh and isinstance(value, dict):
            for key in CREATE_KEYS.get(op.path, ()):
                value[key] = f"{fresh}@example.test" if key == "email" else fresh
        data, headers = json_body(value)
        return data, headers, value

    def disposable(self, op: Operation) -> tuple[dict[str, str], list[tuple[str, str, Any]]]:
        """Path overrides and creation prelude for a uniquely named entity that a
        DELETE scenario may destroy, so the shared world is never deleted (the
        pinned server keeps a deleted API cached, which would desynchronise the
        two worlds for every later scenario)."""
        name = f"sysd{self.counter:05d}"
        rest = self.synth.world.rest_upstream
        api = {"api_name": name, "api_version": "v1", "api_servers": [rest], "api_type": "REST",
               "api_allowed_roles": ["admin", "sysfull"], "api_allowed_groups": ["ALL"], "active": True}
        endpoint = {"api_name": name, "api_version": "v1", "endpoint_method": "GET",
                    "endpoint_uri": "/items", "endpoint_description": "disposable"}
        kinds: list[tuple[str, dict[str, str], list[tuple[str, str, Any]]]] = [
            ("/platform/api/{api_name}/{api_version}", {"api_name": name},
             [("POST", "/platform/api", api)]),
            ("/platform/endpoint/{endpoint_method}/{api_name}/{api_version}/{endpoint_uri}",
             {"api_name": name}, [("POST", "/platform/api", api), ("POST", "/platform/endpoint", endpoint)]),
            ("/platform/proto/{api_name}/{api_version}", {"api_name": name},
             [("POST", "/platform/api", api), ("PROTO", f"/platform/proto/{name}/v1", None)]),
            ("/platform/group/{group_name}", {"group_name": name},
             [("POST", "/platform/group", {"group_name": name, "group_description": "disposable"})]),
            ("/platform/role/{role_name}", {"role_name": name},
             [("POST", "/platform/role", {"role_name": name, "role_description": "disposable"})]),
            ("/platform/routing/{client_key}", {"client_key": name},
             [("POST", "/platform/routing", {"client_key": name, "routing_name": "disposable",
                                              "routing_servers": [rest], "routing_description": "d"})]),
            ("/platform/user/{username}", {"username": name},
             [("POST", "/platform/user", {"username": name, "email": f"{name}@example.test",
                                          "password": WORLD_PASSWORD, "role": "sysrole", "groups": ["sysgroup"]})]),
            ("/platform/vault/{key_name}", {"key_name": name},
             [("POST", "/platform/vault", {"key_name": name, "value": "disposable-value", "description": "d"})]),
            ("/platform/credit/{api_credit_group}", {"api_credit_group": name},
             [("POST", "/platform/credit", {"api_credit_group": name, "api_key": "disposable-key-0001",
                                            "api_key_header": "x-api-key", "credit_tiers": []})]),
            ("/platform/tiers/{tier_id}", {"tier_id": name},
             [("POST", "/platform/tiers/", {"tier_id": name, "name": "custom", "display_name": "D",
                                           "limits": {"requests_per_minute": 1000000000}})]),
            ("/platform/rate-limits/{rule_id}", {"rule_id": name},
             [("POST", "/platform/rate-limits/", {"rule_id": name, "rule_type": "per_user", "target_identifier": "sysuser",
                                                 "time_window": "minute", "limit": 1000000000})]),
        ]
        for template, overrides, prelude in kinds:
            if op.path == template:
                return overrides, prelude
        return {}, []

    def prepare(self, op: Operation, case: str, target: Target) -> Prepared:
        fresh = f"sysn{self.counter:05d}" if op.method == "POST" and op.path in CREATE_KEYS else None
        body, headers, value = self.body(op, fresh)
        overrides, prelude = self.disposable(op) if op.method == "DELETE" else ({}, [])
        prepared = Prepared(op.method, self.render_path(op, target, overrides), body, dict(headers))
        prepared.prelude.extend(prelude)
        admin = target.tokens["sysadmin"]
        if case in ("success", "memory_storage", "external_storage", "cross_node"):
            # cross_node: the world was written through one node; read/act through the other.
            prepared.cross_node = case == "cross_node"
            return prepared
        if case == "lifecycle":
            prepared.repeat = 2
            return prepared
        if case == "idempotent_repeat" or case == "duplicate_resource":
            prepared.repeat = 2
            return prepared
        if case == "anonymous":
            prepared.token_key = None
        elif case == "authenticated":
            prepared.token_key = "sysadmin"
        elif case == "expired_token":
            prepared.raw_token = remint(admin, target.jwt_secret, exp=int(time.time()) - 3600, iat=int(time.time()) - 7200)
        elif case == "malformed_token":
            prepared.raw_token = "not.a.valid-jwt"
        elif case == "wrong_issuer":
            prepared.raw_token = remint(admin, target.jwt_secret, iss="https://issuer.invalid")
        elif case == "wrong_audience":
            prepared.raw_token = remint(admin, target.jwt_secret, aud="audience.invalid")
        elif case == "revoked_token":
            prepared.token_key = "sysrevoke"
            prepared.prelude.append(("POST", "/platform/authorization/admin/revoke/sysrevoke", None))
        elif case == "invalidated_token":
            prepared.token_key = "sysinval"
            prepared.prelude.append(("SELF", "/platform/authorization/invalidate", None))
        elif case == "disabled_user":
            prepared.token_key = "sysdisabled"
            prepared.prelude.append(("PUT", "/platform/user/sysdisabled", {"active": False}))
        elif case == "missing_permission":
            prepared.token_key = "sysuser"
        elif case == "wrong_group":
            prepared.token_key = "sysuser"
        elif case == "subscription_present":
            prepared.token_key = "sysadmin"
        elif case == "subscription_absent":
            prepared.token_key = "sysuser"
        elif case == "missing_body":
            prepared.body, prepared.headers = None, {}
        elif case == "malformed_body":
            prepared.body, prepared.headers = b'{"unterminated": ', {"Content-Type": "application/json"}
        elif case == "wrong_content_type":
            prepared.headers["Content-Type"] = "text/plain"
        elif case == "wrong_scalar_type":
            if isinstance(value, dict) and value:
                mutated = dict(value)
                key = sorted(mutated)[0]
                mutated[key] = {"unexpected": [1, 2]} if not isinstance(mutated[key], dict) else 12345
                prepared.body, prepared.headers = json_body(mutated)
            else:
                prepared.body, prepared.headers = json_body([{"unexpected": True}])
        elif case == "boundary_value":
            if isinstance(value, dict):
                schema = self.synth.schema(op.body_schema)
                mutated = dict(value)
                for key, prop in schema.get("properties", {}).items():
                    prop = self.synth.schema(prop)
                    if key in mutated and "maxLength" in prop and isinstance(mutated[key], str):
                        mutated[key] = (mutated[key] + "b" * 512)[: int(prop["maxLength"]) + 1]
                    elif key in mutated and prop.get("type") == "integer":
                        mutated[key] = -1
                prepared.body, prepared.headers = json_body(mutated)
            else:
                prepared.path = self.render_path(op, target, {name: "b" * 300 for name in PATH_VALUES})
        elif case == "unknown_field":
            if isinstance(value, dict):
                prepared.body, prepared.headers = json_body({**value, "system_e2e_unknown": {"x": 1}})
        elif case == "oversized_body":
            prepared.body = b'{"pad":"' + b"a" * OVERSIZED_BYTES + b'"}'
            prepared.headers = {"Content-Type": "application/json"}
        elif case == "missing_resource":
            prepared.path = self.render_path(op, target, {name: "sysmissing" for name in PATH_VALUES})
        elif case == "conflict":
            if isinstance(value, dict):
                mutated = dict(value)
                for key in ("api_name", "role_name", "group_name", "username", "client_key", "key_name", "tier_id", "rule_id"):
                    if key in mutated:
                        mutated[key] = {"api_name": "sysapi", "username": "sysadmin", "role_name": "sysfull"}.get(key, mutated[key])
                prepared.body, prepared.headers = json_body(mutated)
            prepared.repeat = 2
        elif case == "invalid_transition":
            if op.method == "DELETE":
                prepared.repeat = 2
            else:
                prepared.token_key = "sysdisabled"
                prepared.prelude.append(("PUT", "/platform/user/sysdisabled", {"active": False}))
        elif case == "unsupported_method":
            prepared.method = "TRACE" if op.method != "TRACE" else "PATCH"
        elif case == "incorrect_path":
            prepared.path = prepared.path.split("?", 1)[0].rstrip("/") + "/system-e2e-extra/segment"
        elif case == "invalid_query":
            separator = "&" if "?" in prepared.path else "?"
            prepared.path += separator + "page=-1&page_size=not-a-number&limit=%ZZ"
        elif case == "missing_header":
            if prepared.body is not None:
                prepared.headers.pop("Content-Type", None)
            else:
                prepared.headers["Accept"] = ""
        else:
            raise ValueError(f"unknown operation class: {case}")
        return prepared


# --------------------------------------------------------------------------- execution


# Principals whose session a class deliberately destroys.
RELOGIN = {"revoked_token": ("sysrevoke",), "invalidated_token": ("sysinval",),
           "disabled_user": ("sysdisabled",), "invalid_transition": ("sysdisabled",)}


@dataclass
class Outcome:
    scenario_id: str
    passed: bool
    signatures: dict[str, Any]
    reason: str = ""


class Executor:
    def __init__(
        self,
        candidate: Target,
        oracle: Target,
        world: World,
        approvals: list[Approval],
        log: Callable[[str], None] = print,
    ):
        self.candidate, self.oracle, self.world = candidate, oracle, world
        _, self.document = load_openapi(OPENAPI)
        self.ops = operations(self.document)
        self.builder = Builder(Synthesizer(self.document, world))
        self.approvals = approvals
        self.log = log
        self.secrets = [
            candidate.admin_password, candidate.jwt_secret, WORLD_PASSWORD,
            "sys-vault-secret-value-0001",
        ]

    def setup(self) -> None:
        for target in (self.candidate, self.oracle):
            target.tokens["admin"] = target.login(target.admin_email, target.admin_password)
            self.world.ensure(target)
            self.world.refresh_tokens(target)
        self.tokens_issued = time.monotonic()

    def restore(self, relogin: tuple[str, ...] = ()) -> None:
        for target in (self.candidate, self.oracle):
            self.world.ensure(target)
            for username in relogin:
                target.tokens[username] = self.world.principal_login(target, username)

    def discard_scenario_entities(self, target: Target, owned: str, digest: dict[str, list[str]]) -> None:
        paths = {"apis": "/platform/api/{}/v1", "roles": "/platform/role/{}", "groups": "/platform/group/{}",
                 "users": "/platform/user/{}", "routings": "/platform/routing/{}"}
        for collection, names in digest.items():
            for name in names:
                if SCENARIO_NAME.fullmatch(name) and name.endswith(owned):
                    target.call("DELETE", paths[collection].format(name))

    def perform(self, target: Target, prepared: Prepared) -> Response:
        for method, path, value in prepared.prelude:
            if method == "PROTO":
                boundary = "----system-e2e-disposable"
                data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"d.proto\"\r\n"
                        f"Content-Type: application/octet-stream\r\n\r\n{FIXTURE_PROTO}\r\n--{boundary}--\r\n").encode()
                send(target.base, "POST", path, token=target.tokens["admin"], body=data,
                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, timeout=15)
            elif method == "SELF":
                send(target.base, "POST", path, token=target.tokens[prepared.token_key or "admin"])
            else:
                target.call(method, path, value)
        token = prepared.raw_token or (target.tokens.get(prepared.token_key) if prepared.token_key else None)
        base = target.peer if prepared.cross_node and target.peer else target.base
        response = Response(0, {}, b"")
        for _ in range(prepared.repeat):
            response = send(base, prepared.method, prepared.path, token=token,
                            body=prepared.body, headers=prepared.headers, timeout=15)
        return response

    def redaction_errors(self, response: Response) -> list[str]:
        haystack = response.body + json.dumps(response.headers).encode()
        return [f"secret #{index} disclosed" for index, secret in enumerate(self.secrets) if secret and secret.encode() in haystack]

    def run(self, scenario_id: str) -> Outcome:
        # Sessions expire after 30 minutes and the corpus runs longer than that.
        if time.monotonic() - self.tokens_issued > 20 * 60:
            for target in (self.candidate, self.oracle):
                self.world.refresh_tokens(target)
            self.tokens_issued = time.monotonic()
        _, method, path, case = scenario_id.split("::")
        op = self.ops[(method, path)]
        self.builder.counter += 1
        per_target = {}
        for target in (self.candidate, self.oracle):
            counter = self.builder.counter
            prepared = self.builder.prepare(op, case, target)
            self.builder.counter = counter
            per_target[target.name] = self.perform(target, prepared)
        rust, python = per_target[self.candidate.name], per_target[self.oracle.name]
        signatures = {"candidate": rust.signature(), "oracle": python.signature()}
        reasons: list[str] = []
        if signatures["candidate"] != signatures["oracle"]:
            reasons.append("signature differs from pinned oracle")
        reasons += self.redaction_errors(rust)
        if rust.status < 500 and rust.status != 599 and not all(h in rust.headers for h in SECURITY_HEADERS):
            if (method, path) != ("GET", "/api/health") and not path.startswith("/api/"):
                reasons.append("missing security headers")
        mutated = (method in MUTATING or case in ("revoked_token", "invalidated_token", "disabled_user", "invalid_transition")) and (
            rust.status < 400 or python.status < 400 or case in ("revoked_token", "invalidated_token", "disabled_user", "invalid_transition")
        )
        if mutated:
            before = (self.world.digest(self.candidate), self.world.digest(self.oracle))
            if before[0] != before[1]:
                owned = f"{self.builder.counter:05d}"

                def world_only(digest: dict[str, list[str]]) -> dict[str, list[str]]:
                    return {key: [name for name in names if not SCENARIO_NAME.fullmatch(name)]
                            for key, names in digest.items()}

                approved_signature = any(a.covers(scenario_id, signatures) for a in self.approvals)
                if world_only(before[0]) != world_only(before[1]) or not approved_signature:
                    reasons.append("state digest differs from pinned oracle")
                    signatures["state"] = {"candidate": before[0], "oracle": before[1]}
            # Drop what this scenario created so later scenarios (and the
            # dashboard lists) see only the world.
            owned = f"{self.builder.counter:05d}"
            for target, digest in zip((self.candidate, self.oracle), before):
                self.discard_scenario_entities(target, owned, digest)
            relogin = RELOGIN.get(case, ())
            if path.startswith("/platform/authorization/admin/"):
                # These routes act on the shared principal (disable/revoke).
                for target in (self.candidate, self.oracle):
                    for action in ("enable", "unrevoke"):
                        target.call("POST", f"/platform/authorization/admin/{action}/sysuser")
                relogin += ("sysuser",)
            self.restore(relogin)
        only_signature = reasons == ["signature differs from pinned oracle"]
        approved = next((a for a in self.approvals if a.covers(scenario_id, signatures)), None)
        if only_signature and approved:
            return Outcome(scenario_id, True, signatures, f"approved: {approved.rationale}")
        return Outcome(scenario_id, not reasons, signatures, "; ".join(reasons))


@dataclass
class Approval:
    """A reviewed divergence: `scenario_id` is an anchored regex and
    `signature` pins the exact candidate/oracle fields being approved, so an
    approval never silently covers a different failure on the same cell."""

    pattern: re.Pattern[str]
    signature: dict[str, dict[str, Any]]
    rationale: str

    def covers(self, scenario_id: str, signatures: dict[str, Any]) -> bool:
        if not self.pattern.fullmatch(scenario_id):
            return False
        for side, expected in self.signature.items():
            observed = signatures.get(side, {})
            for key, value in expected.items():
                # {"one_of": [...]} pins a field to a reviewed set of values.
                if isinstance(value, dict) and "one_of" in value:
                    if observed.get(key) not in value["one_of"]:
                        return False
                elif observed.get(key) != value:
                    return False
        return True


def load_approvals() -> list[Approval]:
    value = json.loads((SYSTEM / "approvals.json").read_text())
    return [
        Approval(re.compile(item["scenario_id"]), item["signature"], item["rationale"])
        for item in value.get("approvals", [])
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--candidate-peer", help="second candidate node sharing storage (cross_node cells)")
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--jwt-secret", required=True)
    parser.add_argument("--rest-upstream", required=True)
    parser.add_argument("--upstream", action="append", default=[], help="protocol=url, e.g. soap=http://...")
    parser.add_argument("--filter", default="", help="regex over scenario ids")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    from scripts.system_e2e import generated_ledger

    ledger = generated_ledger()
    ids = [s["id"] for s in ledger["scenarios"] if s["executor"] == "openapi-operation" and re.search(args.filter, s["id"])]
    candidate = Target("candidate", args.candidate.rstrip("/"), args.admin_email, args.admin_password, args.jwt_secret,
                       peer=args.candidate_peer.rstrip("/") if args.candidate_peer else None)
    oracle = Target("oracle", args.oracle.rstrip("/"), args.admin_email, args.admin_password, args.jwt_secret)
    executor = Executor(candidate, oracle, World(args.rest_upstream, dict(item.split("=", 1) for item in args.upstream)), load_approvals())
    executor.setup()
    outcomes = []
    started = time.monotonic()
    for scenario_id in ids:
        outcome = executor.run(scenario_id)
        outcomes.append(outcome)
        if not outcome.passed:
            print(f"FAIL {scenario_id}: {outcome.reason} {json.dumps(outcome.signatures, sort_keys=True)}", flush=True)
    failed = sum(not o.passed for o in outcomes)
    print(f"operation scenarios={len(outcomes)} passed={len(outcomes) - failed} failed={failed} elapsed={time.monotonic() - started:.1f}s")
    if args.report:
        args.report.write_text(json.dumps([o.__dict__ for o in outcomes], indent=1, sort_keys=True) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
