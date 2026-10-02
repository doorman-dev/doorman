#!/usr/bin/env python3
"""Playwright executor for the `ui::<route>` scenarios of the system E2E corpus.

Runs inside the official Playwright image on the system E2E network against the
candidate dashboard after the operation corpus has seeded its world.  Every
dashboard route is opened as the administrator, the way a user reaches it (detail
pages receive the selected entity through sessionStorage exactly as their list
pages hand it over), and checked for:

  route          the page is reached (no redirect to /login or /403), document < 400
  backend_effect the seeded world entity the page is about is rendered
  console        no console errors, no uncaught page errors, no framework error overlay
  network        no gateway call (/platform, /api) answered with a 5xx or 401
  accessibility  a non-empty <title>, an html lang attribute, and one main/landmark region
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from playwright.sync_api import Page, sync_playwright

PUBLIC_ROUTES = {"/login", "/403", "/public"}
# Pages that are about a seeded world entity: (entity kind, sessionStorage key or None)
LIST_TEXT = {
    "/apis": "sysapi", "/groups": "sysgroup", "/roles": "sysrole",
    # Routing client keys are masked in the list; its name is shown instead.
    "/routings": "system e2e",
    "/users": "sysuser", "/credit-defs": "syscredit", "/tiers": "System",  # tier display name
}


def unwrap(value: Any) -> Any:
    while isinstance(value, dict) and isinstance(value.get("response"), (dict, list)):
        value = value["response"]
    return value


class World:
    def __init__(self, page: Page, web: str):
        self.page, self.web = page, web

    def get(self, path: str) -> Any:
        try:
            response = self.page.request.get(self.web + path)
            return unwrap(response.json()) if response.ok else None
        except Exception:  # noqa: BLE001 -- a missing lookup only weakens that route's check
            return None

    def resolve(self) -> dict[str, Any]:
        api = self.get("/platform/api/sysapi/v1") or {}
        tiers = self.get("/platform/tiers/") or {}
        return {
            "api": api,
            "group": self.get("/platform/group/sysgroup") or {"group_name": "sysgroup"},
            "role": self.get("/platform/role/sysrole") or {"role_name": "sysrole"},
            "routing": self.get("/platform/routing/sysclient") or {"client_key": "sysclient"},
            "user": self.get("/platform/user/sysuser") or {"username": "sysuser"},
            "tier": "systier" if "systier" in json.dumps(tiers) else None,
        }


def plan(route: str, world: dict[str, Any]) -> tuple[str, dict[str, Any], str | None]:
    """URL, sessionStorage items, and the text the page must show."""
    api = world["api"]
    api_id = str(api.get("api_id") or "sysapi")
    substitutions = {
        "[apiId]": api_id, "[username]": "sysuser", "[group]": "syscredit", "[groupName]": "sysgroup",
        "[roleName]": "sysrole", "[clientKey]": "sysclient", "[id]": "systier",
    }
    url = route
    for placeholder, value in substitutions.items():
        url = url.replace(placeholder, value)
    storage: dict[str, Any] = {}
    expected = LIST_TEXT.get(route)
    if route.startswith("/apis/[apiId]"):
        storage["selectedApi"] = api
        expected = "sysapi"
    elif route == "/groups/[groupName]":
        storage["selectedGroup"], expected = world["group"], "sysgroup"
    elif route == "/roles/[roleName]":
        storage["selectedRole"], expected = world["role"], "sysrole"
    elif route == "/routings/[clientKey]":
        storage["selectedRouting"], expected = world["routing"], "sysclient"
    elif route == "/users/[username]":
        storage["selectedUser"], expected = world["user"], "sysuser"
    elif route in ("/authorizations/[username]", "/credits/[username]"):
        expected = "sysuser"
    elif route == "/credit-defs/[group]":
        expected = "syscredit"
    elif route.startswith("/tiers/[id]"):
        expected = "System"
    return url, storage, expected


def check(page: Page, web: str, route: str, url: str, storage: dict[str, Any], expected: str | None) -> list[str]:
    console: list[str] = []
    failed: list[str] = []
    page.on("console", lambda message: console.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: console.append(f"pageerror: {error}"))

    def record(response: Any) -> None:
        path = re.sub(r"^https?://[^/]+", "", response.url)
        if (path.startswith("/platform") or path.startswith("/api/")) and (
            response.status >= 500 or response.status == 401
        ):
            failed.append(f"{response.request.method} {path} -> {response.status}")

    page.on("response", record)
    if storage:
        page.goto(web + "/403")
        page.evaluate("items => { for (const [k, v] of Object.entries(items)) sessionStorage.setItem(k, JSON.stringify(v)) }",
                      storage)
    document = page.goto(web + url, wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle", timeout=20000)
    problems: list[str] = []
    final = re.sub(r"^https?://[^/]+", "", page.url).split("?", 1)[0]
    if document is None or document.status >= 400:
        problems.append(f"document status {document.status if document else 'none'}")
    if route not in PUBLIC_ROUTES and (final.startswith("/login") or final.startswith("/403")):
        problems.append(f"redirected to {final}")
    # Form pages show the entity in input values rather than text nodes.
    text = page.inner_text("body") + " " + " ".join(
        page.eval_on_selector_all("input, textarea, select", "items => items.map(item => item.value)"))
    if "Application error" in text or "Unhandled Runtime Error" in text:
        problems.append("framework error overlay")
    if expected and expected not in text:
        # Search filters only the loaded page; page forward like a user would.
        next_button = page.get_by_role("button", name="Next", exact=True)
        for _ in range(25):
            if expected in text or not next_button.count() or next_button.first.is_disabled():
                break
            next_button.first.click()
            page.wait_for_load_state("networkidle", timeout=20000)
            page.wait_for_timeout(300)
            text = page.inner_text("body")
    if expected and expected not in text:
        problems.append(f"backend entity {expected!r} not rendered")
    # Next.js dev noise and aborted navigations are not product errors.
    # The browser ignores COOP on the plain-HTTP test network (a transport
    # artifact, not an application error).
    errors = [line for line in console
              if ("Failed to load resource" not in line or "401" in line or "500" in line)
              and "Cross-Origin-Opener-Policy header has been ignored" not in line
              and "Origin-Agent-Cluster" not in line]
    if errors:
        problems.append("console errors: " + "; ".join(errors[:3]))
    if failed:
        problems.append("failed gateway calls: " + "; ".join(failed[:3]))
    if not (page.title() or "").strip():
        problems.append("missing document title")
    if not page.evaluate("document.documentElement.lang"):
        problems.append("missing html lang")
    if route not in PUBLIC_ROUTES and page.locator("main, [role=main], nav, [role=navigation]").count() == 0:
        problems.append("no landmark region")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--web", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--routes", type=Path, required=True, help="JSON list of dashboard routes")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    routes = json.loads(args.routes.read_text())
    outcomes = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        login_page = context.new_page()
        login = login_page.request.post(args.web + "/platform/authorization",
                                        data={"email": args.admin_email, "password": args.admin_password})
        if not login.ok:
            print(f"administrator login through the dashboard origin failed: HTTP {login.status}", file=sys.stderr)
            return 2
        # Give the administrator the seeded tier so quota pages show real data.
        login_page.request.post(args.web + "/platform/tiers/assignments", data={"user_id": "admin", "tier_id": "systier"})
        world = World(login_page, args.web).resolve()
        login_page.close()
        for route in routes:
            url, storage, expected = plan(route, world)
            page = context.new_page()
            try:
                problems = check(page, args.web, route, url, storage, expected)
            except Exception as error:  # noqa: BLE001 -- a crashed check is a failed scenario
                problems = [f"{type(error).__name__}: {error}"]
            finally:
                page.close()
            outcomes.append({"scenario_id": f"ui::{route}", "passed": not problems, "url": url,
                             "reason": "; ".join(problems)})
            print(("PASS " if not problems else "FAIL ") + f"ui::{route} {'; '.join(problems)}", flush=True)
        browser.close()
    args.report.write_text(json.dumps(outcomes, indent=1) + "\n")
    failed = sum(not item["passed"] for item in outcomes)
    print(f"ui scenarios={len(outcomes)} passed={len(outcomes) - failed} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
