#!/usr/bin/env python3
"""Differential executor for the generated pairwise policy matrix.

Every `pairwise::NNNN` row of the system E2E ledger fixes one value on each of
the 22 policy axes in system-tests/pairwise.json.  The executor turns the row
into a concrete world on both the candidate and the pinned Python oracle -- a
dedicated API, endpoint set, principal, credit group, tier, routing, upstream
fault programme and request -- sends the same request to both, and compares
the response signatures exactly like the operation executor.  Differences pass
only through system-tests/approvals.json.

Rows are executed by the topology named on their `storage` axis, so a memory
run executes the memory rows and the external / two-node runs execute theirs.

Axis mapping (kept deliberately literal so a failing row is easy to replay):
  api_mode        public -> api_public; optional -> api_auth_required=false; private -> both false/true
  authentication  anonymous -> no token; valid/optional -> principal token; invalid -> garbage token
  role / group    api_allowed_roles / api_allowed_groups include or exclude the principal's
  subscription    principal subscribed or not
  credit          api_credits_enabled with a per-row credit group; exhausted = 0 credits
  tier_quota      per-row tier assigned to the principal; exhausted = 1 req/min after a warm-up
  rate_limit      user rate limit 1000/min or 1/min after a warm-up
  throttle        user throttle 1/s with a short wait (delay) or a queue of 1 after two warm-ups
  bandwidth       user bandwidth large, or 1 byte after a warm-up
  ip_mode         whitelist/blacklist of every address (0.0.0.0/0, ::/0)
  trusted_proxy   X-Forwarded-For 203.0.113.7, trusted per API or not
  cors            Origin header against api_cors_* settings (credentials adds allow-credentials)
  routing         api servers / endpoint_servers / client-key routing to the row's upstream
  resilience      retry count 2; circuit-open = three failing warm-ups; half-open = that plus 1.1s
  transformation  api_request_transform / api_response_transform header additions
  compression     Accept-Encoding gzip (REST gzip rows read the fixture's /gzip resource)
  body_size       no body / 1 KiB body / 12 MiB body
  upstream        fixture faults: 503, 400, 2.5s latency, disconnect, malformed body
  active_state    API "active": false, or the requested endpoint left unregistered
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.system_operations import (  # noqa: E402
    FIXTURE_PROTO, OVERSIZED_BYTES, UNLIMITED, WORLD_PASSWORD, Response, Target, World,
    json_body, load_approvals, send,
)

PRINCIPAL_ROLE = "sysfull"
PRINCIPAL_GROUP = "sysgroup"
ORIGIN_ALLOWED = "https://pairwise.example.test"
ORIGIN_DENIED = "https://denied.example.test"
SOAP_ENVELOPE = b'<?xml version="1.0"?><Envelope><Body><Ping/></Body></Envelope>'


@dataclass
class Plan:
    """One row made concrete for a single target."""

    api: dict[str, Any]
    endpoints: list[tuple[str, str]]
    user: dict[str, Any]
    subscribe: bool
    credits: int | None
    tier_limit: int | None
    faults: dict[str, Any]
    warmups: int
    pause: float
    method: str
    path: str
    headers: dict[str, str]
    body: bytes | None
    token: str | None = None
    routing: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


def protocol_of(profile: str) -> str:
    return profile.rsplit("-", 1)[0]


class Pairwise:
    def __init__(self, candidate: Target, oracle: Target, world: World,
                 controls: dict[str, str], log: Callable[[str], None] = print):
        self.candidate = candidate
        self.oracle = oracle
        self.world = world
        # protocol -> fixture control base (grpc is controlled over its HTTP port)
        self.controls = controls
        self.approvals = load_approvals()
        self.log = log

    # ----------------------------------------------------------------- planning

    def upstream(self, profile: str) -> str:
        return self.world.upstreams[profile]

    def plan(self, index: int, row: dict[str, str]) -> Plan:
        protocol = protocol_of(row["protocol_profile"])
        name = f"pw{index:04d}"
        upstream = self.upstream(row["protocol_profile"])
        api_type = {"rest": "REST", "graphql": "GRAPHQL", "soap": "SOAP", "grpc": "GRPC", "grpc-web": "GRPC"}[protocol]
        api: dict[str, Any] = {
            "api_name": name, "api_version": "v1", "api_description": f"pairwise row {index}",
            "api_allowed_roles": [PRINCIPAL_ROLE] if row["role_permission"] == "allowed" else ["pwnobody"],
            "api_allowed_groups": [PRINCIPAL_GROUP] if row["group_eligibility"] == "allowed" else ["pwnogroup"],
            "api_servers": [upstream], "api_type": api_type,
            "api_allowed_retry_count": 2 if row["resilience"] == "retry" else 0,
            "api_public": row["api_mode"] == "public",
            "api_auth_required": row["api_mode"] == "private",
            "active": row["active_state"] != "api-inactive",
        }
        if protocol == "grpc-web":
            api["api_grpc_web_enabled"] = True
        if row["credit"] != "disabled":
            api.update(api_credits_enabled=True, api_credit_group=f"{name}c")
        if row["ip_mode"] != "disabled":
            key = "api_ip_whitelist" if row["ip_mode"] == "allow" else "api_ip_blacklist"
            api.update(api_ip_mode="whitelist" if row["ip_mode"] == "allow" else "blacklist",
                       **{key: ["0.0.0.0/0", "::/0"]})
        if row["trusted_proxy"] == "trusted":
            api["api_trust_x_forwarded_for"] = True
        if row["cors"] != "none":
            api.update(api_cors_allow_origins=[ORIGIN_ALLOWED], api_cors_allow_methods=["GET", "POST"],
                       api_cors_allow_headers=["*"], api_cors_allow_credentials=row["cors"] == "credentials")
        if row["transformation"] in ("request", "both"):
            api["api_request_transform"] = {"request": {"headers": {"add": {"X-Pairwise": "1"}}}}
        if row["transformation"] in ("response", "both"):
            api["api_response_transform"] = {"response": {"headers": {"add": {"X-Pairwise-Response": "1"}}}}

        user = dict(UNLIMITED)
        if row["rate_limit"] != "disabled":
            user.update(rate_limit_enabled=True, rate_limit_duration=1000 if row["rate_limit"] == "available" else 1,
                        rate_limit_duration_type="minute")
        if row["throttle"] != "disabled":
            user.update(throttle_enabled=True, throttle_duration=1, throttle_duration_type="second",
                        throttle_wait_duration=0.2, throttle_wait_duration_type="second",
                        throttle_queue_limit=10 if row["throttle"] == "delay" else 1)
        if row["bandwidth"] != "disabled":
            user.update(bandwidth_limit_enabled=True, bandwidth_limit_window="minute",
                        bandwidth_limit_bytes=10_000_000 if row["bandwidth"] == "available" else 1)

        faults: dict[str, Any] = {
            "success": {}, "retryable": {"statuses": [503]}, "nonretryable": {"statuses": [400]},
            "timeout": {"latency_ms": 2500}, "disconnect": {"disconnect": True}, "malformed": {"malformed": True},
        }[row["upstream"]]
        warmups = max(
            1 if row["tier_quota"] == "exhausted" else 0,
            1 if row["rate_limit"] == "limited" else 0,
            1 if row["throttle"] == "delay" else 2 if row["throttle"] == "queue-full" else 0,
            1 if row["bandwidth"] == "exhausted" else 0,
            3 if row["resilience"] in ("circuit-open", "half-open") else 0,
        )
        if row["resilience"] in ("circuit-open", "half-open"):
            faults = {**faults, "statuses": [500, 500, 500, *faults.get("statuses", [])]}

        method, path, headers, body, endpoints = self.request(protocol, row, name)
        if row["active_state"] == "endpoint-inactive":
            endpoints = []
        if row["cors"] != "none":
            headers["Origin"] = ORIGIN_DENIED if row["cors"] == "denied" else ORIGIN_ALLOWED
        if row["trusted_proxy"] != "off":
            headers["X-Forwarded-For"] = "203.0.113.7"
        if row["compression"] != "off":
            headers["Accept-Encoding"] = "gzip"
        if row["routing"] == "client":
            headers["client-key"] = f"{name}r"
        return Plan(
            api=api, endpoints=endpoints, user=user, subscribe=row["subscription"] == "present",
            credits=None if row["credit"] == "disabled" else (100 if row["credit"] == "positive" else 0),
            tier_limit=None if row["tier_quota"] == "none" else (1000 if row["tier_quota"] == "available" else 1),
            faults=faults, warmups=warmups, pause=1.1 if row["resilience"] == "half-open" else 0.0,
            method=method, path=path, headers=headers, body=body,
            routing=row["routing"] == "client",
            extra={"endpoint_servers": row["routing"] == "endpoint", "auth": row["authentication"],
                   "protocol": protocol, "profile": row["protocol_profile"], "upstream": upstream},
        )

    def request(self, protocol: str, row: dict[str, str], name: str
                ) -> tuple[str, str, dict[str, str], bytes | None, list[tuple[str, str]]]:
        size = row["body_size"]

        def sized(default: bytes) -> bytes | None:
            if size == "empty":
                return None
            if size == "oversized":
                return b'{"pad":"' + b"a" * OVERSIZED_BYTES + b'"}'
            return default

        if protocol == "rest":
            resource = "/gzip" if row["compression"] == "gzip" else "/items"
            if size == "empty":
                return "GET", f"/api/rest/{name}/v1{resource}", {}, None, [("GET", resource)]
            padded = json.dumps({"pad": "a" * 1000}).encode()
            return ("POST", f"/api/rest/{name}/v1{resource}", {"Content-Type": "application/json"},
                    sized(padded), [("POST", resource)])
        if protocol == "graphql":
            return ("POST", f"/api/graphql/{name}", {"Content-Type": "application/json", "X-API-Version": "v1"},
                    sized(b'{"query":"{ hello }"}'), [("POST", "/graphql")])
        if protocol == "soap":
            media = "application/soap+xml" if row["protocol_profile"] == "soap-2" else "text/xml"
            return ("POST", f"/api/soap/{name}/v1/soap", {"Content-Type": media},
                    sized(SOAP_ENVELOPE), [("POST", "/soap")])
        if protocol == "grpc":
            return ("POST", f"/api/grpc/{name}", {"Content-Type": "application/json", "X-API-Version": "v1"},
                    sized(b'{"method":"Resource.Create","message":{"name":"probe"}}'), [("POST", "/grpc")])
        frame = b"\x00\x00\x00\x00\x07\x0a\x05probe"
        if row["protocol_profile"] == "grpc-web-2":
            return ("POST", f"/grpc-web/{name}/fixture.v1.Resource/Create",
                    {"Content-Type": "application/grpc-web-text", "X-API-Version": "v1"},
                    sized(base64.b64encode(frame)), [("POST", "/grpc")])
        return ("POST", f"/grpc-web/{name}/fixture.v1.Resource/Create",
                {"Content-Type": "application/grpc-web+proto", "X-API-Version": "v1"},
                sized(frame), [("POST", "/grpc")])

    # ----------------------------------------------------------------- world

    def principal(self, target: Target, name: str, plan: Plan) -> str:
        username = f"{name}u"
        call = target.call
        user = {"username": username, "email": f"{username}@example.test", "password": WORLD_PASSWORD,
                "role": PRINCIPAL_ROLE, "groups": [PRINCIPAL_GROUP], "active": True, "ui_access": True}
        if call("POST", "/platform/user", user).status not in (200, 201):
            call("PUT", f"/platform/user/{username}", {"role": PRINCIPAL_ROLE, "groups": [PRINCIPAL_GROUP]})
        call("PUT", f"/platform/user/{username}", plan.user)
        return username

    def build(self, target: Target, name: str, plan: Plan) -> None:
        call = target.call
        username = self.principal(target, name, plan)
        token = target.login(f"{username}@example.test", WORLD_PASSWORD)
        if plan.credits is not None:
            group = plan.api["api_credit_group"]
            call("POST", "/platform/credit", {
                "api_credit_group": group, "api_key": f"{group}-secret-key-0001", "api_key_header": "x-api-key",
                "credit_tiers": [{"tier_name": "basic", "credits": 100, "input_limit": 0, "output_limit": 0,
                                  "reset_frequency": "monthly"}]})
            # The pinned route credits the caller, so the principal credits itself.
            call("POST", f"/platform/credit/{username}", {
                "username": username,
                "users_credits": {group: {"tier_name": "basic", "available_credits": plan.credits}}}, token=token)
        if call("POST", "/platform/api", plan.api).status not in (200, 201):
            call("PUT", f"/platform/api/{name}/v1",
                 {k: v for k, v in plan.api.items() if k not in ("api_name", "api_version")})
        for method, uri in plan.endpoints:
            endpoint: dict[str, Any] = {"api_name": name, "api_version": "v1", "endpoint_method": method,
                                        "endpoint_uri": uri, "endpoint_description": "pairwise"}
            if plan.extra["endpoint_servers"]:
                endpoint["endpoint_servers"] = [plan.extra["upstream"]]
            call("POST", "/platform/endpoint", endpoint)
        if plan.extra["protocol"] in ("grpc", "grpc-web"):
            boundary = "----system-e2e-pairwise"
            data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.proto\"\r\n"
                    f"Content-Type: application/octet-stream\r\n\r\n{FIXTURE_PROTO}\r\n--{boundary}--\r\n").encode()
            send(target.base, "POST", f"/platform/proto/{name}/v1", token=target.tokens["admin"], body=data,
                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        if plan.routing:
            routing = {"client_key": f"{name}r", "routing_name": "pairwise",
                       "routing_servers": [plan.extra["upstream"]], "routing_description": "pairwise"}
            call("POST", "/platform/routing", routing)
        if plan.subscribe:
            call("POST", "/platform/subscription/subscribe",
                 {"username": username, "api_name": name, "api_version": "v1"})
        if plan.tier_limit is not None:
            tier = f"{name}t"
            call("POST", "/platform/tiers/", {"tier_id": tier, "name": "custom", "display_name": tier,
                                               "limits": {"requests_per_minute": plan.tier_limit}})
            call("POST", "/platform/tiers/assignments", {"user_id": username, "tier_id": tier})
        auth = plan.extra["auth"]
        plan.token = None if auth == "anonymous" else ("not-a-valid-token" if auth == "invalid" else token)

    def program(self, profile: str, faults: dict[str, Any]) -> None:
        control = self.controls[profile]
        for path, value in (("/__control/reset", {}), ("/__control/faults", faults)):
            request = urllib.request.Request(control + path, data=json.dumps(value).encode(),
                                             headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(request, timeout=5).read()

    def fire(self, target: Target, plan: Plan) -> Response:
        profile = plan.extra["profile"]
        # Two-node rows are configured through one node and exercised through the other.
        base = target.peer or target.base
        self.program(profile, plan.faults)
        for _ in range(plan.warmups):
            send(base, plan.method, plan.path, token=plan.token, body=plan.body,
                 headers=plan.headers, timeout=15)
        if plan.pause:
            time.sleep(plan.pause)
        response = send(base, plan.method, plan.path, token=plan.token, body=plan.body,
                        headers=plan.headers, timeout=15)
        self.program(profile, {})
        return response

    # ----------------------------------------------------------------- run

    def run(self, index: int, row: dict[str, str]) -> dict[str, Any]:
        scenario_id = f"pairwise::{index:04d}"
        responses: dict[str, Response] = {}
        for target in (self.candidate, self.oracle):
            plan = self.plan(index, row)
            self.build(target, f"pw{index:04d}", plan)
            responses[target.name] = self.fire(target, plan)
        candidate, oracle = responses[self.candidate.name], responses[self.oracle.name]
        signatures = {"candidate": candidate.signature(), "oracle": oracle.signature()}
        for side in signatures.values():
            side.pop("allow", None)
        reasons = []
        if signatures["candidate"] != signatures["oracle"]:
            reasons.append("signature differs from pinned oracle")
        if candidate.status == 599 or oracle.status == 599:
            reasons.append("gateway request failed at the test client (HTTP 599)")
        secrets = (self.candidate.admin_password, self.candidate.jwt_secret, WORLD_PASSWORD)
        haystack = candidate.decoded_body() + json.dumps(candidate.headers).encode()
        reasons += [f"secret #{i} disclosed" for i, secret in enumerate(secrets) if secret and secret.encode() in haystack]
        approved = None
        if reasons == ["signature differs from pinned oracle"]:
            approved = next((a for a in self.approvals if a.covers(scenario_id, signatures)), None)
        passed = not reasons or approved is not None
        reason = f"approved: {approved.rationale}" if approved else "; ".join(reasons)
        self.log(f"{'PASS' if passed else 'FAIL'} {scenario_id} {json.dumps(row, sort_keys=True)} "
                 f"{reason} {json.dumps(signatures, sort_keys=True)}")
        return {"scenario_id": scenario_id, "passed": passed, "signatures": signatures, "reason": reason,
                "inputs": row}

    def setup(self) -> None:
        for target in (self.candidate, self.oracle):
            target.tokens["admin"] = target.login(target.admin_email, target.admin_password)
            self.world.ensure(target)


def main() -> int:
    from scripts.system_e2e import generated_ledger

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--jwt-secret", required=True)
    parser.add_argument("--rest-upstream", required=True)
    parser.add_argument("--upstream", action="append", default=[], help="profile=url")
    parser.add_argument("--control", action="append", default=[], help="profile=fixture control url")
    parser.add_argument("--storage", default="memory")
    parser.add_argument("--filter", default="")
    parser.add_argument("--report")
    args = parser.parse_args()
    upstreams = dict(item.split("=", 1) for item in args.upstream)
    upstreams.setdefault("rest-1", args.rest_upstream)
    controls = dict(item.split("=", 1) for item in args.control)
    profiles = {row["protocol_profile"] for row in generated_ledger()["pairwise_rows"]}
    if missing := sorted(profiles - upstreams.keys()):
        parser.error(f"missing upstream profiles: {', '.join(missing)}")
    if missing := sorted(profiles - controls.keys()):
        parser.error(f"missing fixture controls: {', '.join(missing)}")
    for protocol, profile in (("soap", "soap-1"), ("graphql", "graphql-1"), ("grpc", "grpc-1")):
        upstreams.setdefault(protocol, upstreams[profile])
    runner = Pairwise(
        Target("candidate", args.candidate, args.admin_email, args.admin_password, args.jwt_secret),
        Target("oracle", args.oracle, args.admin_email, args.admin_password, args.jwt_secret),
        World(args.rest_upstream, upstreams), controls,
    )
    runner.setup()
    outcomes = []
    for index, row in enumerate(generated_ledger()["pairwise_rows"], 1):
        if row["storage"] != args.storage or (args.filter and args.filter not in f"pairwise::{index:04d}"):
            continue
        outcomes.append(runner.run(index, row))
    failed = [item for item in outcomes if not item["passed"]]
    if args.report:
        Path(args.report).write_text(json.dumps(outcomes, indent=1) + "\n")
    print(f"pairwise scenarios={len(outcomes)} passed={len(outcomes) - len(failed)} failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
