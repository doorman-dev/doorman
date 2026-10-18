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

**Goal:** Publish `/api/rest/customers/v1/*` → `http://httpbin.org` with automatic API key injection.

### 1. Create Token Group

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit" -d '{
    "api_credit_group": "demo-customers",
    "api_key": "demo-secret-123",
    "api_key_header": "x-api-key",
    "credit_tiers": [
      {
        "tier_name": "default",
        "credits": 999999,
        "input_limit": 0,
        "output_limit": 0,
        "reset_frequency": "monthly"
      }
    ]
  }'
```

### 2. Create API

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api" -d '{
    "api_name": "customers",
    "api_version": "v1",
    "api_description": "Demo customers API",
    "api_allowed_roles": ["admin"],
    "api_allowed_groups": ["ALL"],
    "api_servers": ["http://httpbin.org"],
    "api_type": "REST",
    "api_allowed_retry_count": 0,
    "api_allowed_headers": ["content-type", "accept"],
    "api_credits_enabled": true,
    "api_credit_group": "demo-customers"
  }'
```

### 3. Add Endpoints

```bash
# GET endpoint
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint" -d '{
    "api_name": "customers",
    "api_version": "v1",
    "endpoint_method": "GET",
    "endpoint_uri": "/get",
    "endpoint_description": "Echo GET request"
  }'

# POST endpoint
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint" -d '{
    "api_name": "customers",
    "api_version": "v1",
    "endpoint_method": "POST",
    "endpoint_uri": "/post",
    "endpoint_description": "Echo POST request"
  }'
```

### 4. Subscribe User

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/subscription/subscribe" -d '{
    "username": "admin",
    "api_name": "customers",
    "api_version": "v1"
  }'
```

### 5. Test

```bash
curl -sb "$COOKIE" "$BASE/api/rest/customers/v1/get?demo=1"
```

---

## Workflow 2: Client-Specific Routing

**Goal:** Route clients to different upstream pools via `client-key` header.

### 1. Create Routing Entries

```bash
# Enterprise client routing
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/routing" -d '{
    "routing_name": "customers-enterprise",
    "routing_servers": ["http://premium-upstream-a:8080", "http://premium-upstream-b:8080"],
    "routing_description": "Premium pool for enterprise clients",
    "client_key": "enterprise-A"
  }'

# Free tier client routing
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/routing" -d '{
    "routing_name": "customers-free",
    "routing_servers": ["http://shared-upstream:8080"],
    "routing_description": "Shared pool for free tier",
    "client_key": "free-tier"
  }'
```

### 2. Test

```bash
# Enterprise tier
curl -sb "$COOKIE" -H 'client-key: enterprise-A' "$BASE/api/rest/customers/v1/get"

# Free tier
curl -sb "$COOKIE" -H 'client-key: free-tier' "$BASE/api/rest/customers/v1/get"
```

---

## Workflow 3: Per-User Token Management

**Goal:** Track per-user credits and inject user-specific API keys.

### 1. Create Token Group

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit" -d '{
    "api_credit_group": "openai-api",
    "api_key": "default-openai-key",
    "api_key_header": "Authorization",
    "credit_tiers": [
      {
        "tier_name": "free",
        "credits": 1000,
        "input_limit": 100,
        "output_limit": 100,
        "reset_frequency": "monthly"
      },
      {
        "tier_name": "premium",
        "credits": 100000,
        "input_limit": 10000,
        "output_limit": 10000,
        "reset_frequency": "monthly"
      }
    ]
  }'
```

### Step 2: Assign User-Specific API Key

User-specific keys override the group default.

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit/alice" -d '{
    "api_credit_group": "openai-api",
    "api_key": "ALICE-PERSONAL-OPENAI-KEY",
    "api_key_header": "Authorization",
    "credit_tiers": [
      {
        "tier_name": "premium",
        "credits": 100000,
        "input_limit": 10000,
        "output_limit": 10000,
        "reset_frequency": "monthly"
      }
    ]
  }'
```

### Step 3: Create API with Credits Enabled

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api" -d '{
    "api_name": "openai",
    "api_version": "v1",
    "api_description": "OpenAI API proxy",
    "api_allowed_roles": ["user", "admin"],
    "api_allowed_groups": ["ALL"],
    "api_servers": ["https://api.openai.com"],
    "api_type": "REST",
    "api_credits_enabled": true,
    "api_credit_group": "openai-api",
    "api_allowed_headers": ["content-type", "authorization"]
  }'
```

### Step 4: Call Gateway

When Alice calls the gateway:
- Doorman injects her personal API key
- Deducts credits from her account
- Returns 401 with error code `GTW008` when credits run out

```bash
# Alice's call (uses her personal key and credits)
curl -s -b "$COOKIE" -H 'Content-Type: application/json' \
  -d '{"prompt": "Hello world"}' \
  "$BASE/api/rest/openai/v1/completions"
```

**Credit tracking:**
- Input/output tokens counted against limits
- Credits reset based on `reset_frequency`
- View credit usage via `/platform/credit/{username}`

---

## Workflow 4: GraphQL Gateway

**Scenario:** Proxy a public GraphQL API with optional validation.

**Gateway path:** `/api/graphql/{apiName}`

**Required header:** `X-API-Version: v1`

### Step 1: Create GraphQL API

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api" -d '{
    "api_name": "countries",
    "api_version": "v1",
    "api_description": "Public GraphQL API for country data",
    "api_allowed_roles": ["admin", "user"],
    "api_allowed_groups": ["ALL"],
    "api_servers": ["https://countries.trevorblades.com"],
    "api_type": "GraphQL",
    "api_allowed_headers": ["content-type"],
    "api_allowed_retry_count": 0
  }'
```

### Step 2: Subscribe User

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/subscription/subscribe" -d '{
    "username": "admin",
    "api_name": "countries",
    "api_version": "v1"
  }'
```

### Step 3: Call GraphQL Gateway

```bash
curl -s -b "$COOKIE" \
  -H 'Content-Type: application/json' \
  -H 'X-API-Version: v1' \
  -d '{"query":"{ country(code: \"US\") { name capital currency } }"}' \
  "$BASE/api/graphql/countries"
```

**Optional: Add GraphQL validation**

Attach validation to verify operation shape and variables:

```json
{
  "api_validation_enabled": true,
  "api_validation_schema": {
    "query": {"required": true, "type": "string"},
    "variables": {"required": false, "type": "object"}
  }
}
```

---

## Workflow 5: SOAP Gateway

**Scenario:** Proxy legacy SOAP APIs with XML validation.

**Gateway path:** `/api/soap/{path}`

### Step 1: Create SOAP API

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api" -d '{
    "api_name": "legacy-orders",
    "api_version": "v1",
    "api_description": "Legacy SOAP order service",
    "api_allowed_roles": ["admin"],
    "api_allowed_groups": ["internal"],
    "api_servers": ["http://legacy-soap.internal:8080"],
    "api_type": "SOAP",
    "api_allowed_retry_count": 1,
    "api_allowed_headers": ["content-type", "soapaction"]
  }'
```

### Step 2: Add SOAP Endpoints

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint" -d '{
    "api_name": "legacy-orders",
    "api_version": "v1",
    "endpoint_method": "POST",
    "endpoint_uri": "/OrderService/CreateOrder",
    "endpoint_description": "SOAP CreateOrder operation"
  }'
```

### Step 3: Add XML Validation (Optional)

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint/endpoint/validation" -d '{
    "endpoint_id": "<endpoint_id>",
    "validation_enabled": true,
    "validation_schema": {
      "validation_schema": {
        "orderId": {"required": true, "type": "string"},
        "customerId": {"required": true, "type": "string"}
      }
    }
  }'
```

### Step 4: Call SOAP Gateway

```bash
curl -s -b "$COOKIE" \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: CreateOrder' \
  -d '<soap:Envelope>...</soap:Envelope>' \
  "$BASE/api/soap/legacy-orders/v1/OrderService/CreateOrder"
```

---

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
| `X-API-Lifecycle-Status` | Every response once the version resolves | `deprecated` |
| `X-API-Resolved-Version` | Every response once the version resolves | `v1.1.0` |
| `Deprecation` (RFC 9745) | Deprecated or retired | `@1792108800` |
| `Sunset` (RFC 8594) | Deprecated or retired | `Sat, 01 May 2027 00:00:00 GMT` |
| `Link` | A successor is set | `</api/rest/orders/v2>; rel="successor-version"` |

The headers are also sent on error responses after resolution, such as `401`, `403` (`GTW012`), `404` and `429`, so clients can see the lifecycle even when a call fails.

When CORS applies, these headers are added to `Access-Control-Expose-Headers` so browser clients can read them. A retired version's `410` keeps the API's CORS headers too.

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

Send the major version to change every release in the line whose current status allows the transition. Deprecation requires a future `retirement_date`. The whole request is checked before anything is written, so if any release would be rejected (for example, with no valid retirement date), no release changes.

```bash
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api/orders/v1/lifecycle" -d '{
    "status": "deprecated",
    "retirement_date": "2027-05-01",
    "successor_version": "v2",
    "note": "v2 adds pagination"
  }'
```

`successor_version` must name a routable version of the same API. Leave it out to keep the saved successor, or send `""` (or `null`) to clear it.

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

**Allowed transitions:** draft → active, active → deprecated, deprecated → active or retired, retired → deprecated (undo). Lifecycle changes need the `manage_apis` permission. Each change is written to the audit log and to the version's `api_lifecycle_history`. Updating an API with `PUT /platform/api/{name}/{version}` leaves its lifecycle fields unchanged. A config import (`POST /platform/config/import`) restores `api_lifecycle_status` as given, without transition rules, but rejects the whole import with `400` (`API014`) if any status isn't one of `draft`, `active`, `deprecated` or `retired`.

Subscriptions can name a major line (`orders/v1`), which covers every release in it, or an exact release. Drafts can't be subscribed to, and retired versions can only be unsubscribed from. The dashboard's **Version Lifecycle** panel on each API page offers the same actions.

---

## Monitoring and Health Checks

### Health Endpoints

```bash
# Liveness probe (basic health)
curl -s "$BASE/platform/monitor/liveness"
# Returns: {"status": "alive"}

# Readiness probe (checks Redis/MongoDB)
curl -s "$BASE/platform/monitor/readiness"
# Returns: {"status": "ready", "mongodb": "connected", "redis": "connected"}

# Gateway status (public endpoint)
curl -s "$BASE/api/health"
# Returns: {"status": "ok", "uptime": 12345, "memory": {...}}
```

### Metrics

```bash
# Requires authentication + manage_gateway permission
curl -s -b "$COOKIE" "$BASE/platform/monitor/metrics?range=24h"
```

**Metrics include:**
- Request counts per API
- Average response times
- Error rates
- Credit usage
- Rate limit hits

### Logs

**Via UI:** Navigate to Logging section

**Via API:**
```bash
# View logs (requires view_logs permission)
curl -s -b "$COOKIE" "$BASE/platform/logging/logs?limit=100"

# Export logs (requires export_logs permission)
curl -s -b "$COOKIE" "$BASE/platform/logging/export?start_date=2024-01-01"
```

**Log files:**
- `logs/doorman.log` - Main application log
- `logs/doorman-trail.log` - Audit trail

---

## Common Errors and Troubleshooting

### GTW001: API Not Found

**Error message:** "API not found"

**Causes:**
- API with that name/version doesn't exist
- Typo in `api_name` or `api_version`

**Solutions:**
```bash
# List all APIs
curl -s -b "$COOKIE" "$BASE/platform/api"

# Check API details
curl -s -b "$COOKIE" "$BASE/platform/api/customers/v1"
```

### GTW002: No Endpoints Defined

**Error message:** "No endpoints defined for this API"

**Causes:**
- API created but no endpoints added

**Solutions:**
```bash
# Add at least one endpoint
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint" -d '{
    "api_name": "customers",
    "api_version": "v1",
    "endpoint_method": "GET",
    "endpoint_uri": "/health"
  }'
```

### GTW003: Endpoint Not Found

**Error message:** "Endpoint not found: GET /users"

**Causes:**
- Method/URI combination not added as an endpoint
- Typo in path or method

**Solutions:**
```bash
# List endpoints for API
curl -s -b "$COOKIE" "$BASE/platform/endpoint?api_name=customers&api_version=v1"

# Check URI matches exactly (including leading slash)
# Gateway path: /api/rest/customers/v1/users
# Endpoint URI should be: /users
```

### GTW008: No Credits/Tokens

**Error message:** "No credits available"

**Causes:**
- User ran out of credits
- No token group assigned
- Credits not enabled for API

**Solutions:**
```bash
# Check user's credits
curl -s -b "$COOKIE" "$BASE/platform/credit/{username}"

# Add more credits
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit/{username}" -d '{
    "api_credit_group": "demo-api",
    "credit_tiers": [{"tier_name": "default", "credits": 100000, ...}]
  }'
```

### HTTP 403: Permission Denied

**Error message:** "You do not have permission..."

**Causes:**
- User lacks required role permission
- User not in allowed group for API
- User not subscribed to API

**Solutions:**
```bash
# Check user's roles
curl -s -b "$COOKIE" "$BASE/platform/user/{username}"

# Add required role
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/user/{username}/roles" -d '{
    "roles": ["manage_apis"]
  }'

# Subscribe to API
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/subscription/subscribe" -d '{
    "username": "alice",
    "api_name": "customers",
    "api_version": "v1"
  }'
```

### CORS Errors

**Error:** "CORS policy: No 'Access-Control-Allow-Origin' header"

**Causes:**
- Client origin not in `ALLOWED_ORIGINS`
- Wildcard origin with credentials enabled

**Solutions:**
```bash
# Update environment variable
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
CORS_STRICT=true

# Use CORS checker tool
curl -s -b "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/tools/cors/check" -d '{
    "origin": "https://app.example.com",
    "method": "GET",
    "with_credentials": true
  }'
```

### CSRF Errors

**Error:** "Invalid CSRF token"

**Causes:**
- `X-CSRF-Token` header missing
- CSRF token doesn't match cookie
- HTTPS not properly configured

**Solutions:**
```bash
# Ensure HTTPS is enabled
HTTPS_ONLY=true

# Include CSRF token in request
curl -s -b "$COOKIE" \
  -H "X-CSRF-Token: $(grep csrf_token cookies.txt | awk '{print $7}')" \
  -H 'Content-Type: application/json' \
  -X POST "$BASE/platform/api" -d '{...}'
```

### Request Too Large (413)

**Error code:** `REQ001`

**Causes:**
- Request body exceeds `MAX_BODY_SIZE_BYTES`

**Solutions:**
```bash
# Increase limit for specific API type
MAX_BODY_SIZE_BYTES_SOAP=2097152  # 2MB for SOAP
MAX_BODY_SIZE_BYTES_REST=524288   # 512KB for REST

# Or increase global limit
MAX_BODY_SIZE_BYTES=2097152
```

---

## Tips and Best Practices

### API Configuration

- **Restrict headers:** Only allow headers that upstream needs via `api_allowed_headers`
- **Use retries wisely:** Set `api_allowed_retry_count` based on upstream idempotency
- **Enable validation:** Validate requests at the gateway to protect upstream services
- **Version APIs:** Always use explicit versions (v1, v2, etc.)

### Routing

- **Client routing:** Use `client-key` header for blue/green deployments or premium tiers
- **Server pools:** Provide multiple servers in `api_servers` for load balancing
- **Precedence:** Remember routing > endpoint > API server selection

### Security

- **Subscribe users:** Always require subscriptions to control access
- **Use groups:** Organize users into groups for easier access management
- **Enable credits:** Track and limit usage with credit system
- **Validate inputs:** Add endpoint validation to reject malformed requests early

### Monitoring

- **Enable JSON logs:** Set `LOG_FORMAT=json` in production
- **Ship to SIEM:** Forward logs to centralized log management
- **Monitor metrics:** Regularly review `/platform/monitor/metrics`
- **Set up alerts:** Alert on error rates, credit exhaustion, rate limit hits

### Performance

- **Use Redis:** Enable Redis for distributed rate limiting and caching
- **Connection pooling:** Upstream servers are pooled automatically
- **Limit body sizes:** Set appropriate `MAX_BODY_SIZE_BYTES` per API type
- **Enable compression:** Configure upstream responses with compression

---

## Next Steps

- **[Configuration Reference](./02-configuration.md)** - Complete environment variable guide
- **[Security Guide](./03-security.md)** - Hardening and security best practices
- **[Operations Guide](./05-operations.md)** - Production deployment and runbooks
- **[Tools](./06-tools.md)** - CORS checker and diagnostics
