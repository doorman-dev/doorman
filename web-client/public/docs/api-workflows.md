# API Workflows

End-to-end examples for common API gateway scenarios.

## Setup

```bash
export BASE=http://localhost:3001
export COOKIE=/tmp/doorman.cookies
export DOORMAN_ADMIN_EMAIL="admin@example.com"
export DOORMAN_ADMIN_PASSWORD="YourStrongPassword123!"

# Login once
curl -sc "$COOKIE" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$DOORMAN_ADMIN_EMAIL\",\"password\":\"$DOORMAN_ADMIN_PASSWORD\"}" \
  "$BASE/platform/authorization"
```

---

## Workflow 1: REST API with API Key Injection

Publish `/api/rest/customers/v1/*` → `http://httpbin.org` with automatic API key injection.

```bash
# 1) Create token group
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit" -d '{
    "api_credit_group": "demo-customers",
    "api_key": "demo-secret-123",
    "api_key_header": "x-api-key",
    "credit_tiers": [{"tier_name": "default", "credits": 999999, "reset_frequency": "monthly"}]
  }'

# 2) Create API
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api" -d '{
    "api_name": "customers",
    "api_version": "v1",
    "api_description": "Demo customers API",
    "api_allowed_roles": ["admin"],
    "api_allowed_groups": ["ALL"],
    "api_servers": ["http://httpbin.org"],
    "api_type": "REST",
    "api_credits_enabled": true,
    "api_credit_group": "demo-customers"
  }'

# 3) Add endpoints
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint" -d '{
    "api_name": "customers",
    "api_version": "v1",
    "endpoint_method": "GET",
    "endpoint_uri": "/get"
  }'

# 4) Subscribe user
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/subscription/subscribe" -d '{
    "username": "admin",
    "api_name": "customers",
    "api_version": "v1"
  }'

# 5) Test
curl -sb "$COOKIE" "$BASE/api/rest/customers/v1/get?demo=1"
```

---

## Workflow 2: Client-Specific Routing

Route clients to different upstream pools via `client-key` header.

```bash
# Enterprise routing
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/routing" -d '{
    "routing_name": "customers-enterprise",
    "routing_servers": ["http://premium-upstream-a:8080", "http://premium-upstream-b:8080"],
    "client_key": "enterprise-A"
  }'

# Free tier routing
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/routing" -d '{
    "routing_name": "customers-free",
    "routing_servers": ["http://shared-upstream:8080"],
    "client_key": "free-tier"
  }'

# Test
curl -sb "$COOKIE" -H 'client-key: enterprise-A' "$BASE/api/rest/customers/v1/get"
curl -sb "$COOKIE" -H 'client-key: free-tier' "$BASE/api/rest/customers/v1/get"
```

---

## Workflow 3: Per-User Token Management

Track per-user credits and inject user-specific API keys.

```bash
# Create token group
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit" -d '{
    "api_credit_group": "openai-api",
    "api_key": "default-openai-key",
    "api_key_header": "Authorization",
    "credit_tiers": [{"tier_name": "free", "credits": 1000, "reset_frequency": "monthly"}]
  }'

# Assign personal key to user 'alice'
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit/alice" -d '{
    "api_credit_group": "openai-api",
    "api_key": "ALICE-PERSONAL-OPENAI-KEY",
    "api_key_header": "Authorization",
    "credit_tiers": [{"tier_name": "premium", "credits": 100000, "reset_frequency": "monthly"}]
  }'
```

## Workflow 6: Versioning and Deprecation

The URI picks the version. Clients call a major line such as `/api/rest/orders/v1/...`, and you can publish semver releases (`v1.0.0`, `v1.1.0`) underneath it. GraphQL and gRPC choose the line with the `X-API-Version` header.

**How a request is resolved**

- A major version (`v1`) goes to the highest release in that line whose status is `active` or `deprecated`. An existing `v1` record counts as `v1.0.0`.
- A dotted (`v1.1.0`) or non-semver (`beta`) version must match a record exactly.
- `draft` releases are never routable. If every release in a line is `retired`, the gateway answers `410 Gone` with error code `GTW015`.
- The `active` toggle is still a separate kill switch. A disabled API returns `403` (`GTW012`).

**Response headers**

| Header | Sent when | Example |
| :--- | :--- | :--- |
| `X-API-Lifecycle-Status` | Always | `deprecated` |
| `X-API-Resolved-Version` | Always | `v1.1.0` |
| `Deprecation` (RFC 9745) | Deprecated or retired | `@1792108800` |
| `Sunset` (RFC 8594) | Deprecated or retired | `Sat, 01 May 2027 00:00:00 GMT` |
| `Link` | A successor is set | `</api/rest/orders/v2>; rel="successor-version"` |

When CORS applies, these headers are added to `Access-Control-Expose-Headers` so browser clients can read them.

### Step 1: Publish a release as a draft

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api" -d '{
    "api_name": "orders",
    "api_version": "v1.1.0",
    "api_lifecycle_status": "draft",
    "api_servers": ["http://orders-v1-1:8080"],
    "api_type": "REST"
  }'
```

New APIs start as `active` unless you send `draft`. Add endpoints as usual, then publish:

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api/orders/v1.1.0/lifecycle" -d '{"status": "active"}'
```

### Step 2: Deprecate a major line

Send the major version to change every release in the line whose current status allows the transition. Deprecation requires a future `retirement_date`.

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api/orders/v1/lifecycle" -d '{
    "status": "deprecated",
    "retirement_date": "2027-05-01",
    "successor_version": "v2",
    "note": "v2 adds pagination"
  }'
```

### Step 3: Check the line

```bash
curl -s -b "$COOKIE" "$BASE/platform/api/orders/v1/versions"
curl -si "$BASE/api/rest/orders/v1/items" | grep -iE 'x-api-|sunset|deprecation|link'
```

### Step 4: Retire it

Retirement is always manual. The retirement date only informs consumers.

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api/orders/v1/lifecycle" -d '{"status": "retired"}'
```

Requests to the retired line return `410 Gone`. With the retirement date and successor above, the JSON response is:

```json
{
  "error_code": "GTW015",
  "error_message": "API version has been retired",
  "retirement_date": "2027-05-01T00:00:00Z",
  "successor_version": "v2"
}
```

`retirement_date` is an RFC 3339 UTC timestamp. Either metadata field is `null` when unset. SOAP keeps its XML error body; the lifecycle headers carry the retirement and successor information.

**Allowed transitions:** draft → active, active → deprecated, deprecated → active or retired, retired → deprecated (undo). Lifecycle changes need the `manage_apis` permission. Each change is written to the audit log and to the version's `api_lifecycle_history`. Updating an API with `PUT /platform/api/{name}/{version}` leaves its lifecycle fields unchanged.

Subscriptions can name a major line (`orders/v1`), which covers every release in it, or an exact release. Drafts can't be subscribed to, and retired versions can only be unsubscribed from. The dashboard's **Version Lifecycle** panel on each API page offers the same actions.
