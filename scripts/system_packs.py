#!/usr/bin/env python3
"""Higher-order feature packs for the system E2E corpus (`pack::<name>`).

Each pack is a scripted workflow that combines several features the operation
and pairwise corpora exercise one at a time.  Packs that the pinned Python
server implements compare the observed sequence against the oracle; packs that
exercise candidate-only topologies (two nodes, external storage outages,
snapshot restarts) assert the documented candidate behaviour directly.  A pack
passes only when every assertion holds; the report lists each failed one.
"""

from __future__ import annotations

import base64
import json
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.system_operations import (  # noqa: E402
    FIXTURE_PROTO, FULL_ROLE, UNLIMITED, WORLD_PASSWORD, Response, Target, json_body, send,
)

SECRET_MARKERS = ("pack-vault-secret-7f3a", "pack-credit-key-91bc", "pack-bearer-marker-55d2")


@dataclass
class Topology:
    """Everything the packs can drive.  Absent entries skip nothing: a pack
    whose topology is missing fails with an explicit reason."""

    candidate: Target
    oracle: Target
    upstream: Callable[[str], str]          # profile -> URL as seen by the gateways
    control: dict[str, str]                 # profile -> fixture control URL from here
    memory_container: str | None = None
    external: Target | None = None
    external_redis: str | None = None
    external_mongo: str | None = None
    node_a: Target | None = None
    node_b: Target | None = None
    native_tls: dict[str, str] | None = None
    problems: list[str] = field(default_factory=list)


def unwrap(value: Any) -> Any:
    while isinstance(value, dict) and isinstance(value.get("response"), (dict, list)):
        value = value["response"]
    return value


def fixture(top: Topology, profile: str, path: str, value: Any | None = None) -> Any:
    data = json.dumps(value if value is not None else {}).encode() if path != "/__control/counters" else None
    request = urllib.request.Request(top.control[profile] + path, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def upstream_count(top: Topology, profile: str) -> int:
    return sum(fixture(top, profile, "/__control/counters").get("counts", {}).values())


def principal(target: Target, username: str, groups: list[str], **limits: Any) -> str:
    user = {"username": username, "email": f"{username}@example.test", "password": WORLD_PASSWORD,
            "role": "sysfull", "groups": groups, "active": True, "ui_access": True}
    if target.call("POST", "/platform/user", user).status not in (200, 201):
        target.call("PUT", f"/platform/user/{username}", {"groups": groups, "active": True})
    target.call("PUT", f"/platform/user/{username}", {**UNLIMITED, **limits})
    return target.login(f"{username}@example.test", WORLD_PASSWORD)


def api(target: Target, name: str, servers: list[str], endpoints: list[tuple[str, str]], **fields: Any) -> None:
    body = {"api_name": name, "api_version": "v1", "api_description": "pack", "api_allowed_roles": ["sysfull", "admin"],
            "api_allowed_groups": ["ALL", "sysgroup"], "api_servers": servers, "api_type": "REST",
            "api_allowed_retry_count": 0, "active": True, **fields}
    if target.call("POST", "/platform/api", body).status not in (200, 201):
        target.call("PUT", f"/platform/api/{name}/v1", {k: v for k, v in body.items() if k not in ("api_name", "api_version")})
    for method, uri in endpoints:
        target.call("POST", "/platform/endpoint", {"api_name": name, "api_version": "v1", "endpoint_method": method,
                                                   "endpoint_uri": uri, "endpoint_description": "pack"})


def subscribe(target: Target, username: str, name: str) -> None:
    target.call("POST", "/platform/subscription/subscribe", {"username": username, "api_name": name, "api_version": "v1"})


def statuses(responses: list[Response]) -> list[int]:
    return [response.status for response in responses]


def both(top: Topology, action: Callable[[Target], Any]) -> tuple[Any, Any]:
    return action(top.candidate), action(top.oracle)


def expect(top: Topology, condition: bool, message: str) -> None:
    if not condition:
        top.problems.append(message)


def differential(top: Topology, label: str, action: Callable[[Target], Any]) -> tuple[Any, Any]:
    candidate, oracle = both(top, action)
    expect(top, candidate == oracle, f"{label}: candidate {candidate} != oracle {oracle}")
    return candidate, oracle


# --------------------------------------------------------------------------- packs


def private_role_group_subscription_credits(top: Topology) -> None:
    credit_body = {"username": "pack1u", "users_credits": {
        "packc1": {"tier_name": "basic", "available_credits": 2}}}

    def run(target: Target) -> dict[str, Any]:
        target.call("POST", "/platform/credit", {
            "api_credit_group": "packc1", "api_key": "pack-credit-key-91bc", "api_key_header": "x-api-key",
            "credit_tiers": [{"tier_name": "basic", "credits": 2, "input_limit": 0, "output_limit": 0,
                              "reset_frequency": "monthly"}]})
        api(target, "pack1", [top.upstream("rest-1")], [("GET", "/items")], api_credits_enabled=True,
            api_credit_group="packc1", api_allowed_groups=["sysgroup"])
        token = principal(target, "pack1u", ["sysgroup"])
        target.call("POST", "/platform/credit/pack1u", credit_body, token=token)
        subscribe(target, "pack1u", "pack1")

        def request(auth: str | None = token) -> int:
            return send(target.base, "GET", "/api/rest/pack1/v1/items", token=auth).status

        def credits() -> int | None:
            value = unwrap(target.call("GET", "/platform/credit/pack1u").json())
            group = value.get("users_credits", {}).get("packc1", {}) if isinstance(value, dict) else {}
            return group.get("available_credits")

        result: dict[str, Any] = {
            "anonymous": request(None), "invalid_token": request("not-a-valid-token"),
            "credits_after_auth_denials": credits(),
            "allowed": [request(), request()],
            "credits_after_success": credits(),
            "exhausted": request(),
        }
        target.call("POST", "/platform/credit/pack1u", credit_body, token=token)
        target.call("POST", "/platform/subscription/unsubscribe",
                    {"username": "pack1u", "api_name": "pack1", "api_version": "v1"})
        result["unsubscribed"] = request()
        subscribe(target, "pack1u", "pack1")
        result["resubscribed"] = request()
        target.call("PUT", "/platform/user/pack1u", {"groups": ["other"]})
        result["wrong_group"] = request()
        target.call("PUT", "/platform/user/pack1u", {"groups": ["sysgroup"]})
        target.call("PUT", "/platform/api/pack1/v1", {"api_allowed_roles": ["pwnobody"]})
        result["wrong_role"] = request()
        target.call("PUT", "/platform/api/pack1/v1", {"api_allowed_roles": ["sysfull", "admin"]})
        result["restored"] = request()
        result["credits_after_denials"] = credits()
        return result

    candidate, _ = differential(top, "credits/subscription/group sequence", run)
    expect(top, candidate["allowed"] == [200, 200] and candidate["resubscribed"] == 200
           and candidate["restored"] == 200, f"authorized requests must succeed: {candidate}")
    expect(top, all(400 <= candidate[name] < 500 for name in (
        "anonymous", "invalid_token", "exhausted", "unsubscribed", "wrong_group", "wrong_role"
    )), f"auth, credit, subscription, group and role denials must be 4xx: {candidate}")
    expect(top, candidate["credits_after_auth_denials"] == 2
           and candidate["credits_after_success"] == 0
           and candidate["credits_after_denials"] == 0,
           f"only authorized requests may consume credits: {candidate}")


def optional_anonymous_ip_rate_limit(top: Topology) -> None:
    def run(target: Target) -> list[int]:
        api(target, "pack2", [top.upstream("rest-1")], [("GET", "/items")], api_auth_required=False,
            api_ip_mode="blacklist", api_ip_blacklist=["203.0.113.9"], api_trust_x_forwarded_for=True)
        token = principal(target, "pack2u", ["sysgroup"], rate_limit_enabled=True, rate_limit_duration=1,
                          rate_limit_duration_type="minute")
        subscribe(target, "pack2u", "pack2")
        optional = statuses([
            send(target.base, "GET", "/api/rest/pack2/v1/items"),
            send(target.base, "GET", "/api/rest/pack2/v1/items", headers={"X-Forwarded-For": "203.0.113.9"}),
            send(target.base, "GET", "/api/rest/pack2/v1/items", token=token),
            send(target.base, "GET", "/api/rest/pack2/v1/items", token=token),
        ])
        api(target, "pack2private", [top.upstream("rest-1")], [("GET", "/items")],
            api_auth_required=True, api_ip_mode="blacklist", api_ip_blacklist=["203.0.113.9"],
            api_trust_x_forwarded_for=True)
        subscribe(target, "pack2u", "pack2private")
        private = statuses([
            send(target.base, "GET", "/api/rest/pack2private/v1/items"),
            send(target.base, "GET", "/api/rest/pack2private/v1/items", token=token),
            send(target.base, "GET", "/api/rest/pack2private/v1/items", token=token),
        ])
        return optional + private

    candidate, _ = differential(top, "optional auth / ip / rate sequence", run)
    expect(top, candidate[0] == 200 and candidate[2] == 200,
           f"anonymous and first authenticated requests must succeed: {candidate}")
    expect(top, 400 <= candidate[1] < 500 and candidate[3] == 200,
           f"optional auth must allow valid tokens without a user limit, while blocking the IP: {candidate}")
    expect(top, 400 <= candidate[4] < 500 and candidate[5:] == [200, 429],
           f"private auth must reject anonymity and enforce the user rate limit: {candidate}")


def public_cors_header_response_transform(top: Topology) -> None:
    origin = "https://pack3.example"

    def run(target: Target) -> list[Any]:
        api(target, "pack3", [top.upstream("rest-1")], [("GET", "/items")], api_public=True,
            api_cors_allow_origins=[origin], api_cors_allow_methods=["GET"], api_cors_allow_headers=["X-Custom"],
            api_request_transform={"request": {"headers": {"add": {"X-Pack3": "in"}}}},
            api_response_transform={"response": {"headers": {"add": {"X-Pack3-Out": "out"}}}})
        preflight = send(target.base, "OPTIONS", "/api/rest/pack3/v1/items", headers={
            "Origin": origin, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "X-Custom"})
        denied = send(target.base, "OPTIONS", "/api/rest/pack3/v1/items", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
        fixture(top, "rest-1", "/__control/reset")
        actual = send(target.base, "GET", "/api/rest/pack3/v1/items", headers={"Origin": origin})
        journal = fixture(top, "rest-1", "/__control/journal").get("journal", [])
        forwarded = any(entry.get("headers", {}).get("x-pack3") == "in" for entry in journal)
        return [preflight.status, preflight.headers.get("access-control-allow-origin"),
                denied.headers.get("access-control-allow-origin"), actual.status,
                actual.headers.get("access-control-allow-origin"), actual.headers.get("x-pack3-out"), forwarded]

    candidate, _ = differential(top, "public CORS + transforms", run)
    expect(top, candidate[1] == origin and candidate[2] is None, f"CORS allow/deny wrong: {candidate}")


def routing_override_round_robin_retry_circuit(top: Topology) -> None:
    target = top.candidate
    one, two = top.upstream("rest-1"), top.upstream("rest-2")
    api(target, "pack4", [one, two], [("GET", "/items")])
    subscribe(target, "admin", "pack4")
    token = target.tokens["admin"]
    for profile in ("rest-1", "rest-2"):
        fixture(top, profile, "/__control/reset")
    for _ in range(4):
        send(target.base, "GET", "/api/rest/pack4/v1/items", token=token)
    expect(top, upstream_count(top, "rest-1") >= 1 and upstream_count(top, "rest-2") >= 1,
           "round robin did not reach both upstreams")
    target.call("POST", "/platform/routing", {"client_key": "pack4r", "routing_name": "pack", "routing_servers": [two],
                                              "routing_description": "pack"})
    for profile in ("rest-1", "rest-2"):
        fixture(top, profile, "/__control/reset")
    for _ in range(3):
        send(target.base, "GET", "/api/rest/pack4/v1/items", token=token, headers={"client-key": "pack4r"})
    expect(top, upstream_count(top, "rest-1") == 0 and upstream_count(top, "rest-2") == 3,
           "client routing override not honoured")
    api(target, "pack4b", [one], [("GET", "/items")], api_allowed_retry_count=2)
    subscribe(target, "admin", "pack4b")
    fixture(top, "rest-1", "/__control/reset")
    fixture(top, "rest-1", "/__control/faults", {"statuses": [503, 503]})
    retried = send(target.base, "GET", "/api/rest/pack4b/v1/items", token=token)
    expect(top, retried.status == 200 and upstream_count(top, "rest-1") == 3, f"retry: {retried.status}")
    api(target, "pack4c", [one], [("GET", "/items")])
    subscribe(target, "admin", "pack4c")
    fixture(top, "rest-1", "/__control/reset")
    fixture(top, "rest-1", "/__control/faults", {"statuses": [500] * 20})
    results = [send(target.base, "GET", "/api/rest/pack4c/v1/items", token=token).status for _ in range(8)]
    reached = upstream_count(top, "rest-1")
    expect(top, reached < 8, f"circuit never opened: {reached} upstream calls for {results}")
    fixture(top, "rest-1", "/__control/reset")


def tier_rate_throttle_bandwidth(top: Topology) -> None:
    def run(target: Target) -> list[int]:
        api(target, "pack5", [top.upstream("rest-1")], [("GET", "/items")])
        token = principal(target, "pack5u", ["sysgroup"])
        subscribe(target, "pack5u", "pack5")
        target.call("POST", "/platform/tiers/", {"tier_id": "pack5t", "name": "custom", "display_name": "pack5t",
                                                  "limits": {"requests_per_minute": 2}})
        target.call("POST", "/platform/tiers/assignments", {"user_id": "pack5u", "tier_id": "pack5t"})
        tier = [send(target.base, "GET", "/api/rest/pack5/v1/items", token=token) for _ in range(3)]
        target.call("DELETE", "/platform/tiers/assignments/pack5u")
        target.call("PUT", "/platform/user/pack5u", {"bandwidth_limit_enabled": True, "bandwidth_limit_bytes": 1,
                                                    "bandwidth_limit_window": "minute"})
        bandwidth = [send(target.base, "GET", "/api/rest/pack5/v1/items", token=token) for _ in range(2)]
        return statuses(tier + bandwidth)

    candidate, _ = differential(top, "tier then bandwidth sequence", run)
    expect(top, candidate[:2] == [200, 200] and candidate[2] == 429,
           f"tier must allow two requests then rate-limit the third: {candidate}")
    expect(top, 429 in candidate[3:], f"bandwidth limit was not enforced: {candidate}")


def two_node_policy_membership_revocation(top: Topology) -> None:
    if not (top.node_a and top.node_b):
        top.problems.append("two-node topology not provided")
        return
    a, b = top.node_a, top.node_b
    a.tokens["admin"] = a.login(a.admin_email, a.admin_password)
    a.call("POST", "/platform/group", {"group_name": "pack6g", "group_description": "pack", "api_access": []})
    api(a, "pack6", [top.upstream("rest-1")], [("GET", "/items")], api_allowed_groups=["pack6g"])
    token = principal(a, "pack6u", ["pack6g"])
    subscribe(a, "pack6u", "pack6")
    time.sleep(2)
    expect(top, send(b.base, "GET", "/platform/user/me", token=token).status == 200, "node B rejects a node A session")
    expect(top, send(b.base, "GET", "/api/rest/pack6/v1/items", token=token).status == 200,
           "node B does not see node A's API/subscription")
    a.call("PUT", "/platform/user/pack6u", {"groups": ["sysgroup"]})
    deadline, refused = time.monotonic() + 15, False
    while time.monotonic() < deadline and not refused:
        refused = send(b.base, "GET", "/api/rest/pack6/v1/items", token=token).status in (401, 403)
        time.sleep(0.5)
    expect(top, refused, "group removal on node A never enforced on node B")
    a.call("POST", "/platform/authorization/admin/revoke/pack6u")
    deadline, revoked = time.monotonic() + 15, False
    while time.monotonic() < deadline and not revoked:
        revoked = send(b.base, "GET", "/platform/user/me", token=token).status == 401
        time.sleep(0.5)
    expect(top, revoked, "revocation on node A never enforced on node B")


def openapi_import_mutation_hot_traffic(top: Topology) -> None:
    target = top.candidate
    api(target, "pack7", [top.upstream("rest-1")], [("GET", "/items")], api_openapi_url="/openapi.json")
    subscribe(target, "admin", "pack7")
    token = target.tokens["admin"]
    stop, seen = threading.Event(), []

    def traffic() -> None:
        while not stop.is_set():
            seen.append(send(target.base, "GET", "/api/rest/pack7/v1/items", token=token).status)

    thread = threading.Thread(target=traffic)
    thread.start()
    imported = target.call("POST", "/platform/api/pack7/v1/openapi/import")
    for index in range(10):
        target.call("POST", "/platform/endpoint", {"api_name": "pack7", "api_version": "v1", "endpoint_method": "GET",
                                                   "endpoint_uri": f"/hot{index}", "endpoint_description": "hot"})
        target.call("DELETE", f"/platform/endpoint/GET/pack7/v1/hot{index}")
    stop.set()
    thread.join()
    expect(top, imported.status == 200, f"openapi import failed: {imported.status} {imported.body[:200]!r}")
    expect(top, seen and all(status < 500 for status in seen), f"5xx during hot mutation: {sorted(set(seen))}")


def soap_wssecurity_ip_cors_fault(top: Topology) -> None:
    secured = (b'<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Header><Security>'
               b'<UsernameToken><Username>u</Username></UsernameToken></Security></env:Header><env:Body><Ping/>'
               b'</env:Body></env:Envelope>')
    bare = b'<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body><Ping/></env:Body></env:Envelope>'

    def run(target: Target) -> list[Any]:
        api(target, "pack8", [top.upstream("soap-2")], [("POST", "/soap")], api_type="SOAP",
            api_ip_mode="whitelist", api_ip_whitelist=["0.0.0.0/0", "::/0"],
            api_cors_allow_origins=["https://pack8.example"], api_cors_allow_methods=["POST"])
        subscribe(target, "admin", "pack8")
        token = target.tokens["admin"]
        media = {"Content-Type": "application/soap+xml"}
        ok = send(target.base, "POST", "/api/soap/pack8/v1/soap", token=token, body=secured, headers=media)
        fault = send(target.base, "POST", "/api/soap/pack8/v1/soap", token=token, body=bare, headers=media)
        preflight = send(target.base, "OPTIONS", "/api/soap/pack8/v1/soap", headers={
            "Origin": "https://pack8.example", "Access-Control-Request-Method": "POST"})
        return [ok.status, fault.status, preflight.status, preflight.headers.get("access-control-allow-origin")]

    candidate, _ = differential(top, "SOAP 1.2 security/fault/CORS", run)
    expect(top, candidate[0] == 200, f"secured SOAP call failed: {candidate}")


def graphql_depth_variables_partial_error(top: Topology) -> None:
    def run(target: Target) -> list[Any]:
        api(target, "pack9", [top.upstream("graphql-2")], [("POST", "/graphql")], api_type="GRAPHQL")
        subscribe(target, "admin", "pack9")
        token = target.tokens["admin"]
        headers = {"Content-Type": "application/json", "X-API-Version": "v1"}
        results = []
        for query in ({"query": "{ a { b { c { d { e { f { g } } } } } } }"},
                      {"query": "query($x: String) { hello }", "variables": {"x": "value"}},
                      {"query": "{ partial }"}):
            body, _ = json_body(query)
            response = send(target.base, "POST", "/api/graphql/pack9", token=token, body=body, headers=headers)
            value = response.json()
            results.append([response.status, sorted(value) if isinstance(value, dict) else None])
        return results

    differential(top, "GraphQL depth/variables/partial", run)


def grpc_reflection_allowlist_metadata_retry(top: Topology) -> None:
    target = top.candidate
    api(target, "pack10", [top.upstream("grpc-1")], [("POST", "/grpc")], api_type="GRPC",
        api_grpc_allowed_services=["Resource"], api_grpc_allowed_methods=["Resource.Create"],
        api_allowed_retry_count=1, api_allowed_headers=["x-pack-meta"])
    boundary = "----pack10"
    data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.proto\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n{FIXTURE_PROTO}\r\n--{boundary}--\r\n").encode()
    send(target.base, "POST", "/platform/proto/pack10/v1", token=target.tokens["admin"], body=data,
         headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    subscribe(target, "admin", "pack10")
    token = target.tokens["admin"]
    headers = {"Content-Type": "application/json", "X-API-Version": "v1", "x-pack-meta": "m1"}
    good, _ = json_body({"method": "Resource.Create", "message": {"name": "pack"}})
    bad, _ = json_body({"method": "Resource.Delete", "message": {}})
    allowed = send(target.base, "POST", "/api/grpc/pack10", token=token, body=good, headers=headers)
    denied = send(target.base, "POST", "/api/grpc/pack10", token=token, body=bad, headers=headers)
    fixture(top, "grpc-1", "/__control/reset")
    fixture(top, "grpc-1", "/__control/faults", {"statuses": [14]})
    retried = send(target.base, "POST", "/api/grpc/pack10", token=token, body=good, headers=headers)
    fixture(top, "grpc-1", "/__control/reset")
    expect(top, allowed.status == 200, f"allow-listed method failed: {allowed.status} {allowed.body[:200]!r}")
    expect(top, denied.status in (400, 403, 404), f"method outside the allow-list reached upstream: {denied.status}")
    expect(top, retried.status == 200, f"UNAVAILABLE was not retried: {retried.status} {retried.body[:200]!r}")


def grpc_web_text_cors_trailer_envelope(top: Topology) -> None:
    target = top.candidate
    api(target, "pack11", [top.upstream("grpc-1")], [("POST", "/grpc")], api_type="GRPC", api_grpc_web_enabled=True,
        api_cors_allow_origins=["https://pack11.example"], api_cors_allow_methods=["POST"],
        api_cors_allow_headers=["content-type", "x-grpc-web"])
    boundary = "----pack11"
    data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.proto\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n{FIXTURE_PROTO}\r\n--{boundary}--\r\n").encode()
    send(target.base, "POST", "/platform/proto/pack11/v1", token=target.tokens["admin"], body=data,
         headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    subscribe(target, "admin", "pack11")
    frame = b"\x00\x00\x00\x00\x06\x0a\x04pack"
    response = send(target.base, "POST", "/grpc-web/pack11/fixture.v1.Resource/Create", token=target.tokens["admin"],
                    body=base64.b64encode(frame),
                    headers={"Content-Type": "application/grpc-web-text", "X-API-Version": "v1",
                             "Origin": "https://pack11.example"})
    preflight = send(target.base, "OPTIONS", "/grpc-web/pack11/fixture.v1.Resource/Create", headers={
        "Origin": "https://pack11.example", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-grpc-web"})
    expect(top, response.status == 200, f"grpc-web-text call failed: {response.status}")
    expect(top, response.headers.get("content-type", "").startswith("application/grpc-web-text"),
           f"wrong grpc-web-text media type: {response.headers.get('content-type')}")
    try:
        raw = base64.b64decode(response.body)
    except ValueError:
        raw = b""
        top.problems.append("grpc-web-text body is not base64")
    offset, flags = 0, []
    while offset + 5 <= len(raw):
        flags.append(raw[offset])
        offset += 5 + int.from_bytes(raw[offset + 1:offset + 5], "big")
    expect(top, any(flag & 0x80 for flag in flags), f"response carries no trailer frame (flags {flags})")
    expect(top, preflight.headers.get("access-control-allow-origin") == "https://pack11.example",
           f"grpc-web CORS preflight not allowed: {preflight.status}")


def snapshot_concurrent_restart_restore(top: Topology) -> None:
    if not top.memory_container:
        top.problems.append("memory candidate container not provided")
        return
    target = top.candidate
    names = [f"pack12g{index}" for index in range(20)]
    threads = [threading.Thread(target=target.call, args=("POST", "/platform/group",
                                                          {"group_name": name, "group_description": "snap", "api_access": []}))
               for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    dumped = target.call("POST", "/platform/memory/dump", {})
    expect(top, dumped.status == 200, f"memory dump failed: {dumped.status}")
    subprocess.run(["docker", "restart", top.memory_container], check=True, capture_output=True, timeout=120)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if send(target.base, "GET", "/platform/monitor/liveness", timeout=2).status == 200:
            break
        time.sleep(1)
    target.tokens["admin"] = target.login(target.admin_email, target.admin_password)
    missing = [name for name in names if target.call("GET", f"/platform/group/{name}").status != 200]
    expect(top, not missing, f"groups lost across restart: {missing}")


def redis_outage_cached_auth_recovery(top: Topology) -> None:
    if not (top.external and top.external_redis):
        top.problems.append("external topology not provided")
        return
    target = top.external
    target.tokens["admin"] = target.login(target.admin_email, target.admin_password)
    api(target, "pack13", [top.upstream("rest-1")], [("GET", "/items")])
    subscribe(target, "admin", "pack13")
    token = target.tokens["admin"]
    subprocess.run(["docker", "stop", top.external_redis], check=True, capture_output=True, timeout=60)
    try:
        during = [send(target.base, "GET", "/api/rest/pack13/v1/items", token=token, timeout=10).status for _ in range(3)]
        expect(top, all(status in (200, 503) for status in during),
               f"Redis outage must fail closed (503) or serve cached auth (200): {during}")
    finally:
        subprocess.run(["docker", "start", top.external_redis], check=True, capture_output=True, timeout=60)
    deadline, recovered = time.monotonic() + 60, False
    while time.monotonic() < deadline and not recovered:
        recovered = send(target.base, "GET", "/api/rest/pack13/v1/items", token=token, timeout=10).status == 200
        time.sleep(1)
    expect(top, recovered, "gateway did not recover after Redis returned")


def mongo_stepdown_concurrent_writes(top: Topology) -> None:
    if not (top.external and top.external_mongo):
        top.problems.append("external topology not provided")
        return
    target = top.external
    target.tokens["admin"] = target.login(target.admin_email, target.admin_password)
    results: dict[str, int] = {}

    def write(name: str) -> None:
        results[name] = target.call("POST", "/platform/group",
                                    {"group_name": name, "group_description": "stepdown", "api_access": []}).status

    names = [f"pack14g{index}" for index in range(30)]
    threads = [threading.Thread(target=write, args=(name,)) for name in names]
    for index, thread in enumerate(threads):
        thread.start()
        if index == 10:
            subprocess.run(["docker", "restart", top.external_mongo], check=True, capture_output=True, timeout=120)
    for thread in threads:
        thread.join()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if target.call("GET", "/platform/group/all?page_size=500").status == 200:
            break
        time.sleep(1)
    acknowledged = [name for name, status in results.items() if status in (200, 201)]
    lost = [name for name in acknowledged if target.call("GET", f"/platform/group/{name}").status != 200]
    crashed = [status for status in results.values() if status == 500]
    expect(top, not lost, f"acknowledged writes lost across Mongo restart: {lost}")
    expect(top, not crashed, f"writes during the restart answered 500 instead of a retryable status: {len(crashed)}")


def secret_data_logging_export_redaction(top: Topology) -> None:
    target = top.candidate
    target.call("POST", "/platform/vault", {"key_name": "packsecret", "value": SECRET_MARKERS[0], "description": "pack"})
    target.call("POST", "/platform/credit", {"api_credit_group": "packc15", "api_key": SECRET_MARKERS[1],
                                             "api_key_header": "x-api-key", "credit_tiers": []})
    api(target, "pack15", [top.upstream("rest-1")], [("POST", "/items")])
    subscribe(target, "admin", "pack15")
    body, headers = json_body({"password": SECRET_MARKERS[2], "token": SECRET_MARKERS[2]})
    send(target.base, "POST", "/api/rest/pack15/v1/items", token=target.tokens["admin"], body=body,
         headers={**headers, "X-API-Key": SECRET_MARKERS[1], "X-Debug-Token": SECRET_MARKERS[2]})
    send(target.base, "POST", "/platform/authorization", body=json_body(
        {"email": "nobody@example.test", "password": SECRET_MARKERS[2]})[0], headers=headers)
    time.sleep(1)
    exported = b""
    for path in ("/platform/logging/logs/export?format=json", "/platform/logging/logs/download?format=csv",
                 "/platform/logging/logs?limit=1000"):
        response = target.call("GET", path)
        expect(top, response.status == 200, f"{path} failed: {response.status}")
        exported += response.body
    leaked = [marker for marker in SECRET_MARKERS if marker.encode() in exported]
    expect(top, not leaked, f"secrets present in exported logs: {leaked}")


def native_mtls_auth_rbac_credits(top: Topology) -> None:
    if top.native_tls is None:
        top.problems.append("native TLS candidate not provided")
        return
    native = top.native_tls

    def request(method: str, path: str, value: Any = None, *, token: str | None = None,
                identity: str | None = None) -> Response:
        body, headers = json_body(value) if value is not None else (None, {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        context = ssl.create_default_context(cafile=native["ca"])
        if identity:
            context.load_cert_chain(native[f"{identity}_cert"], native[f"{identity}_key"])
        outgoing = urllib.request.Request(native["base"] + path, data=body, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(outgoing, context=context, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return Response(response.status, {key.lower(): val for key, val in response.headers.items()}, response.read())

    def required(method: str, path: str, value: Any, token: str | None,
                 statuses: tuple[int, ...] = (200, 201)) -> Response:
        response = request(method, path, value, token=token)
        if response.status not in statuses:
            raise RuntimeError(f"native TLS setup {method} {path} returned HTTP {response.status}")
        return response

    admin_login = required("POST", "/platform/authorization", {
        "email": top.candidate.admin_email, "password": top.candidate.admin_password,
    }, None, (200,))
    admin = unwrap(admin_login.json())["access_token"]
    required("POST", "/platform/role", {"role_name": "tlsfull", **FULL_ROLE}, admin)
    required("POST", "/platform/group", {"group_name": "tlsgroup", "group_description": "TLS pack",
                                          "api_access": []}, admin)
    required("POST", "/platform/user", {"username": "tlsuser", "email": "tlsuser@example.test",
                                         "password": WORLD_PASSWORD, "role": "tlsfull", "groups": ["tlsgroup"],
                                         "active": True, "ui_access": True}, admin)
    user_login = required("POST", "/platform/authorization", {
        "email": "tlsuser@example.test", "password": WORLD_PASSWORD,
    }, None, (200,))
    user_token = unwrap(user_login.json())["access_token"]
    required("POST", "/platform/credit", {
        "api_credit_group": "tlsc", "api_key": "tls-credit-key-system-test", "api_key_header": "x-api-key",
        "credit_tiers": [{"tier_name": "basic", "credits": 2, "input_limit": 0, "output_limit": 0,
                          "reset_frequency": "monthly"}],
    }, admin)
    required("POST", "/platform/api", {
        "api_name": "tlspack", "api_version": "v1", "api_description": "native TLS policy pack",
        "api_allowed_roles": ["tlsfull"], "api_allowed_groups": ["tlsgroup"],
        "api_servers": [top.upstream("rest-1")], "api_type": "REST", "active": True,
        "api_auth_required": True, "api_credits_enabled": True, "api_credit_group": "tlsc",
        "api_client_tls_policy": {"mode": "required", "ca_profile_id": "system-client-ca",
                                  "allowed_dns_sans": ["client.system.test"]},
    }, admin)
    required("POST", "/platform/endpoint", {"api_name": "tlspack", "api_version": "v1",
                                             "endpoint_method": "GET", "endpoint_uri": "/items",
                                             "endpoint_description": "TLS pack"}, admin)
    required("POST", "/platform/credit/tlsuser", {"username": "tlsuser", "users_credits": {
        "tlsc": {"tier_name": "basic", "available_credits": 2}}}, admin, (200,))
    required("POST", "/platform/subscription/subscribe", {
        "username": "tlsuser", "api_name": "tlspack", "api_version": "v1",
    }, admin, (200,))

    def credits() -> int | None:
        value = unwrap(request("GET", "/platform/credit/tlsuser", token=admin).json())
        return value.get("users_credits", {}).get("tlsc", {}).get("available_credits") if isinstance(value, dict) else None

    def gateway(*, token: str | None = user_token, identity: str | None = "client") -> Response:
        return request("GET", "/api/rest/tlspack/v1/items", token=token, identity=identity)

    fixture(top, "rest-1", "/__control/reset")
    missing_cert = gateway(identity=None)
    wrong_cert = gateway(identity="wrong")
    missing_token = gateway(token=None)
    expect(top, missing_cert.status == 401 and missing_cert.json().get("error_code") == "TLS001",
           f"missing client certificate was accepted: {missing_cert.status}")
    expect(top, wrong_cert.status == 403 and wrong_cert.json().get("error_code") == "TLS002",
           f"wrong client SAN was accepted: {wrong_cert.status}")
    expect(top, missing_token.status == 401, f"client certificate bypassed authentication: {missing_token.status}")
    expect(top, credits() == 2, "certificate or authentication denials consumed credits")
    expect(top, gateway().status == 200, "valid certificate and user could not reach upstream")
    required("PUT", "/platform/user/tlsuser", {"groups": ["other"]}, admin, (200,))
    wrong_group = gateway()
    required("PUT", "/platform/user/tlsuser", {"groups": ["tlsgroup"]}, admin, (200,))
    required("PUT", "/platform/api/tlspack/v1", {"api_allowed_roles": ["other"]}, admin, (200,))
    wrong_role = gateway()
    required("PUT", "/platform/api/tlspack/v1", {"api_allowed_roles": ["tlsfull"]}, admin, (200,))
    required("POST", "/platform/subscription/unsubscribe", {
        "username": "tlsuser", "api_name": "tlspack", "api_version": "v1",
    }, admin, (200,))
    unsubscribed = gateway()
    expect(top, all(400 <= response.status < 500 for response in (wrong_group, wrong_role, unsubscribed)),
           f"RBAC or subscription bypassed under mTLS: {[r.status for r in (wrong_group, wrong_role, unsubscribed)]}")
    expect(top, credits() == 1, "RBAC or subscription denials consumed credits")
    required("POST", "/platform/subscription/subscribe", {
        "username": "tlsuser", "api_name": "tlspack", "api_version": "v1",
    }, admin, (200,))
    expect(top, gateway().status == 200, "restored mTLS user could not use final credit")
    exhausted = gateway()
    expect(top, 400 <= exhausted.status < 500 and credits() == 0,
           f"credit exhaustion was not enforced under mTLS: {exhausted.status}")
    expect(top, upstream_count(top, "rest-1") == 2, "denied mTLS requests reached the upstream")


PACKS: dict[str, Callable[[Topology], None]] = {
    "private-role-group-subscription-credits": private_role_group_subscription_credits,
    "optional-anonymous-ip-rate-limit": optional_anonymous_ip_rate_limit,
    "public-cors-header-response-transform": public_cors_header_response_transform,
    "routing-override-round-robin-retry-circuit": routing_override_round_robin_retry_circuit,
    "tier-rate-throttle-bandwidth": tier_rate_throttle_bandwidth,
    "two-node-policy-membership-revocation": two_node_policy_membership_revocation,
    "openapi-import-mutation-hot-traffic": openapi_import_mutation_hot_traffic,
    "soap-wssecurity-ip-cors-fault": soap_wssecurity_ip_cors_fault,
    "graphql-depth-variables-partial-error": graphql_depth_variables_partial_error,
    "grpc-reflection-allowlist-metadata-retry": grpc_reflection_allowlist_metadata_retry,
    "grpc-web-text-cors-trailer-envelope": grpc_web_text_cors_trailer_envelope,
    "snapshot-concurrent-restart-restore": snapshot_concurrent_restart_restore,
    "redis-outage-cached-auth-recovery": redis_outage_cached_auth_recovery,
    "mongo-stepdown-concurrent-writes": mongo_stepdown_concurrent_writes,
    "secret-data-logging-export-redaction": secret_data_logging_export_redaction,
    "native-mtls-auth-rbac-credits": native_mtls_auth_rbac_credits,
}


def prepare(top: Topology) -> None:
    """Pack prerequisites on every target, independent of the other corpora:
    the shared role and group, and an administrator without the seeded
    one-request-per-second limit."""
    for target in (top.candidate, top.oracle, top.external, top.node_a):
        if target is None:
            continue
        target.tokens["admin"] = target.login(target.admin_email, target.admin_password)
        target.call("PUT", "/platform/user/admin",
                    {key: value for key, value in UNLIMITED.items() if key != "bandwidth_limit_enabled"})
        if target.call("GET", "/platform/role/sysfull").status != 200:
            target.call("POST", "/platform/role", {"role_name": "sysfull", **FULL_ROLE})
        if target.call("GET", "/platform/group/sysgroup").status != 200:
            target.call("POST", "/platform/group", {"group_name": "sysgroup", "group_description": "packs",
                                                    "api_access": []})


def run_pack(name: str, top: Topology) -> dict[str, Any]:
    top.problems = []
    try:
        PACKS[name](top)
    except Exception as error:  # noqa: BLE001 -- a crashed pack is a failed scenario
        top.problems.append(f"{type(error).__name__}: {error}")
    return {"scenario_id": f"pack::{name}", "passed": not top.problems, "reason": "; ".join(top.problems)}


def main() -> int:
    import argparse
    import re

    parser = argparse.ArgumentParser(description="Run higher-order packs against a candidate and the pinned oracle.")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--jwt-secret", required=True)
    parser.add_argument("--upstream", action="append", default=[], help="profile=url as seen by the gateways")
    parser.add_argument("--control", action="append", default=[], help="profile=fixture control url")
    parser.add_argument("--filter", default="")
    args = parser.parse_args()
    upstreams = dict(item.split("=", 1) for item in args.upstream)
    top = Topology(
        candidate=Target("candidate", args.candidate, args.admin_email, args.admin_password, args.jwt_secret),
        oracle=Target("oracle", args.oracle, args.admin_email, args.admin_password, args.jwt_secret),
        upstream=lambda profile: upstreams[profile], control=dict(item.split("=", 1) for item in args.control),
    )
    prepare(top)
    failed = 0
    for name in PACKS:
        if args.filter and not re.search(args.filter, name):
            continue
        outcome = run_pack(name, top)
        failed += not outcome["passed"]
        print(("PASS " if outcome["passed"] else "FAIL ") + outcome["scenario_id"] + " " + outcome["reason"], flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
