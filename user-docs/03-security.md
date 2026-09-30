# Security Guide

Comprehensive security features and best practices for Doorman API Gateway.

## Overview

Doorman implements defense-in-depth security with multiple layers:

- Transport Layer Security (HTTPS/TLS)
- Authentication and authorization (JWT, RBAC)
- CSRF protection
- CORS policies (platform and per-API)
- IP access control (global and per-API)
- Request validation and size limits
- Security headers
- Audit logging and request tracking
- Encryption at rest

---

## Transport Layer Security

### HTTPS Enforcement

**Production Guard**: When `ENV=production`, Doorman refuses to start unless HTTPS is configured.

```bash
# TLS terminated at reverse proxy (Nginx, Traefik, Caddy, ALB, etc.)
HTTPS_ONLY=true  # Enforces secure cookies and CSRF validation
```

**Security behaviors when HTTPS is enabled:**
- Cookies marked with `Secure` flag (sent only over HTTPS)
- CSRF validation enforced
- HSTS headers sent automatically
- CSP and security headers applied

### HTTP Strict Transport Security (HSTS)

**Auto-enabled** when `HTTPS_ONLY=true`:
```
Strict-Transport-Security: max-age=15552000; includeSubDomains; preload
```

This header tells browsers to:
- Only access the site over HTTPS for the next 6 months
- Apply the policy to all subdomains
- Allow preloading into browser HSTS lists

---

## Authentication and Authorization

### JWT Cookie-Based Authentication

Doorman uses **HttpOnly cookies** to store JWT tokens, preventing XSS attacks:

- **Access token**: Short-lived (default 30 minutes)
- **Refresh token**: Longer-lived (default 7 days)
- Both stored in `HttpOnly` cookies (not accessible via JavaScript)

**Token Configuration:**
```bash
JWT_SECRET_KEY=strong-random-secret-32chars+
AUTH_EXPIRE_TIME=30
AUTH_EXPIRE_TIME_FREQ=minutes
AUTH_REFRESH_EXPIRE_TIME=7
AUTH_REFRESH_EXPIRE_FREQ=days
```

**Token Revocation:**
- Tokens can be revoked per-user or per-JTI
- Revocation list stored in Redis (if enabled) or in-memory
- Database-backed revocation for memory-only mode
- Use `/platform/authorization/invalidate` to revoke tokens

### Role-Based Access Control (RBAC)

Users are assigned roles that grant specific permissions:

**Default roles:**
- `admin`: Full platform access
- `user`: Basic gateway access

**Permission examples:**
- `manage_apis`: Create/update/delete APIs
- `manage_endpoints`: Manage API endpoints
- `manage_users`: User administration
- `view_logs`: Access audit logs
- `manage_security`: Security settings and IP policies
- `manage_tiers`: Create, update, delete and assign rate-limit tiers (`/platform/tiers/*`)
- `manage_rate_limits`: Manage rate-limit rules (`/platform/rate-limits/*`; any signed-in user may read their own `/platform/rate-limits/status`)

> **Upgrade note:** the Python gateway exposed the tier and rate-limit-rule endpoints without authentication. Doorman now requires a signed-in user with the permission above; grant it to any automation that manages tiers or rules.

Only roles flagged `platform_admin`, or named `admin`, bypass API subscriptions.

### Groups and Subscriptions

- Users can belong to groups
- APIs can restrict access to specific groups
- Users must subscribe to an API before calling it through the gateway
- Fine-grained access control per API

---

## CSRF Protection

Doorman uses the **double-submit cookie pattern** for CSRF protection.

**Automatic activation**: CSRF is enforced when `HTTPS_ONLY=true`

**How it works:**
1. Server sets `csrf_token` cookie on login (not HttpOnly)
2. Client reads the cookie value
3. Client includes value in `X-CSRF-Token` header on requests
4. Server validates header matches cookie

**Example request:**
```bash
curl -b cookies.txt \
  -H "X-CSRF-Token: abc123..." \
  -H "Content-Type: application/json" \
  -d '{"api_name": "demo"}' \
  https://api.example.com/platform/api
```

**Protected endpoints:**
- All mutating operations (POST, PUT, DELETE, PATCH)
- Platform configuration endpoints
- User management

**Bypassed endpoints:**
- Public read-only endpoints
- Login/refresh (bootstrap CSRF token)

---

## CORS Security

Doorman provides two levels of CORS control:

### Platform-Level CORS

Controls access to `/platform/*` routes (admin/config APIs):

```bash
ALLOWED_ORIGINS=https://admin.example.com,https://app.example.com
ALLOW_CREDENTIALS=True
ALLOW_METHODS=GET,POST,PUT,DELETE,OPTIONS
ALLOW_HEADERS=Content-Type,X-CSRF-Token,Authorization
CORS_STRICT=true  # Reject wildcard when credentials enabled
```

**Security best practices:**
- Never use `ALLOWED_ORIGINS=*` with `ALLOW_CREDENTIALS=True`
- Set `CORS_STRICT=true` in production
- Explicitly list only necessary origins
- Limit methods and headers to minimum required

### Per-API CORS

Each gateway API can define its own CORS policy via API configuration:

```json
{
  "api_cors_allow_origins": ["https://app.example.com"],
  "api_cors_allow_methods": ["GET", "POST"],
  "api_cors_allow_headers": ["Content-Type", "Authorization"],
  "api_cors_allow_credentials": false,
  "api_cors_expose_headers": ["X-Request-ID", "X-RateLimit-Remaining"]
}
```

**Preflight validation:**
- Origin must be in `api_cors_allow_origins`
- Method must be in `api_cors_allow_methods`
- Headers must be in `api_cors_allow_headers`

---

## IP Access Control

Doorman provides **global (platform-wide)** and **per-API** IP filtering.

### Global IP Policy

Configure via Security Settings UI or API:

```json
{
  "ip_whitelist": ["10.0.0.0/8", "192.168.1.100"],
  "ip_blacklist": ["1.2.3.4", "5.6.7.0/24"],
  "trust_x_forwarded_for": true,
  "xff_trusted_proxies": ["10.0.1.10", "10.0.1.11"]
}
```

**Precedence:**
1. **Blacklist is always evaluated first** – if the client IP matches `ip_blacklist`, access is denied.
2. **Whitelist is evaluated next (if non-empty)** – when a global whitelist is configured, any IP **not** in `ip_whitelist` is denied.

**Client IP detection:**
- Direct connection: Socket IP used
- Behind proxy: Use `X-Forwarded-For`, `X-Real-IP`, or `CF-Connecting-IP` headers
- **Trust validation**: Headers only used if source IP matches `xff_trusted_proxies`

**Localhost bypass:**
```bash
LOCAL_HOST_IP_BYPASS=true  # Allow 127.0.0.1/::1 to bypass (dev only!)
```

Set to `false` in production to prevent localhost abuse.

### Per-API IP Policy

Each API can define additional IP restrictions:

```json
{
  "api_ip_mode": "whitelist",           // "allow_all" (default) or "whitelist"
  "api_ip_whitelist": ["203.0.113.0/24"],
  "api_ip_blacklist": ["203.0.113.50"],  // Always enforced, regardless of mode
  "api_trust_x_forwarded_for": true
}
```

**Evaluation logic:**
- `api_ip_blacklist` is **always** applied first. If the effective client IP matches, the request is denied.
- If `api_ip_mode == "whitelist"` then `api_ip_whitelist` is enforced: the effective IP **must** be in the whitelist or the request is denied.
- If `api_ip_mode == "allow_all"`, the per-API whitelist is ignored, but the blacklist still applies.

**Use cases:**
- Restrict internal APIs to VPN range
- Block abusive IPs per API
- Geo-restriction via proxy headers

**Audit trail**: All IP denials logged with:
- Reason (`blacklisted`, `not_in_whitelist`)
- Source IP and effective IP
- XFF header value if present

---

## Security Headers

Doorman automatically applies security headers to all responses.

### Content Security Policy (CSP)

**Default policy** (restrictive baseline):
```
default-src 'none';
frame-ancestors 'none';
base-uri 'none';
form-action 'self';
img-src 'self' data:;
connect-src 'self';
```

**Override:**
```bash
CONTENT_SECURITY_POLICY="default-src 'self'; script-src 'self' 'unsafe-inline';"
```

### Additional Headers

Applied to every response:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Referrer-Policy` | `no-referrer` | Prevent referrer leakage |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Restrict browser features |
| `Strict-Transport-Security` | `max-age=15552000; includeSubDomains` | Force HTTPS (when enabled) |

---

## Request Validation and Limits

### Body Size Limits

Protect against DoS via large payloads:

```bash
# Global default (1MB)
MAX_BODY_SIZE_BYTES=1048576

# Per-API-type overrides
MAX_BODY_SIZE_BYTES_REST=1048576        # REST: 1MB
MAX_BODY_SIZE_BYTES_SOAP=2097152        # SOAP: 2MB (larger XML envelopes)
MAX_BODY_SIZE_BYTES_GRAPHQL=524288      # GraphQL: 512KB (queries are smaller)
MAX_BODY_SIZE_BYTES_GRPC=1048576        # gRPC: 1MB

# Multipart uploads (proto files, etc.)
MAX_MULTIPART_SIZE_BYTES=10485760       # 10MB
```

**Enforcement:**
- Checks `Content-Length` header before reading body
- Returns `413 Payload Too Large` with error code `REQ001`
- Logs violation to audit trail
- Applied universally to all routes

### Endpoint-Level Validation

Attach JSON schema validation to endpoints:

```json
{
  "endpoint_id": "abc123",
  "validation_enabled": true,
  "validation_schema": {
    "user.name": {"required": true, "type": "string", "min": 2},
    "user.email": {"required": true, "type": "string", "format": "email"}
  }
}
```

**Benefits:**
- Requests failing validation return 400 without hitting upstream
- Reduces load on backend services
- Provides consistent error messages

---

## Audit Trail and Logging

### Request ID Propagation

Every request gets a unique ID for tracing:

**Headers accepted:**
- `X-Request-ID` (preferred)
- `Request-ID`

**Headers returned:**
- `X-Request-ID`
- `request_id`

**Usage:**
- All logs include request ID
- Search logs by request ID for full trace
- Pass to upstream services for distributed tracing

### Audit Trail

Separate audit log: `doorman-trail.log`

**Logged events:**
- User authentication (login, logout, refresh)
- Authorization changes (role/group assignments)
- IP policy violations
- Security configuration changes
- API/endpoint creation/deletion
- Token revocation

**Log structure:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "abc123",
  "username": "admin",
  "action": "api.create",
  "target": "orders/v1",
  "status": "success",
  "client_ip": "192.168.1.100",
  "effective_ip": "203.0.113.50",
  "details": {"api_type": "REST"}
}
```

### Log Redaction

Sensitive data automatically redacted:

**Patterns redacted:**
- `Authorization: Bearer [REDACTED]`
- `"access_token": "[REDACTED]"`
- `"refresh_token": "[REDACTED]"`
- `"password": "[REDACTED]"`
- `Cookie: [REDACTED]`
- `X-CSRF-Token: [REDACTED]`

**Applied to:**
- File logs
- Console output
- Audit logs

---

## Encryption and Secrets

### API Key Encryption

Encrypt API keys at rest:

```bash
TOKEN_ENCRYPTION_KEY=your-strong-encryption-key-32chars+
```

**Transparent encryption:**
- Encrypt when storing API keys in database/memory
- Decrypt when injecting into requests
- Uses Fernet symmetric encryption

### Memory Dump Encryption

Required for memory-only mode dumps:

```bash
MEM_ENCRYPTION_KEY=your-memory-dump-encryption-key-32chars+
MEM_DUMP_PATH=data/memory_dump.bin
```

**Security:**
- AES encryption via Fernet
- Dumps written on shutdown or manual save
- Restored automatically on startup

### JWT Secret

**Critical:** This key signs all access tokens.

```bash
JWT_SECRET_KEY=strong-random-secret-change-this-in-production
```

**Best practices:**
- Use at least 32 random characters
- Store in secret manager (Vault, AWS Secrets Manager, etc.)
- Rotate periodically (requires token invalidation)
- Never commit to version control

---

## Security Best Practices

### Production Checklist

- [ ] Set `ENV=production`
- [ ] Enable HTTPS (`HTTPS_ONLY=true`)
- [ ] Use valid TLS certificates (not self-signed)
- [ ] Change `JWT_SECRET_KEY` from default
- [ ] Set strong `TOKEN_ENCRYPTION_KEY` and `MEM_ENCRYPTION_KEY`
- [ ] Configure explicit `ALLOWED_ORIGINS` (no wildcard)
- [ ] Set `CORS_STRICT=true`
- [ ] Configure `COOKIE_DOMAIN` to match your domain
- [ ] Set `LOCAL_HOST_IP_BYPASS=false`
- [ ] Enable `LOG_FORMAT=json` for structured logs
- [ ] Configure IP whitelisting/blacklisting as needed
- [ ] Set appropriate `MAX_BODY_SIZE_BYTES` limits
- [ ] Enable Redis for distributed rate limiting
- [ ] Enable MongoDB for persistence
- [ ] Review and test CSRF protection
- [ ] Configure trusted proxy IPs if behind load balancer
- [ ] Rotate admin password after initial setup
- [ ] Create least-privilege users for operations
- [ ] Enable audit log monitoring

### Development vs Production

| Feature | Development | Production |
|---------|-------------|------------|
| HTTPS Required | Optional | **Required** |
| CSRF Validation | Optional | **Enabled** |
| CORS | Permissive (`*`) | **Strict whitelist** |
| Cookie Secure Flag | No | **Yes** |
| HSTS Header | No | **Yes** |
| Log Format | Plain | **JSON** |
| IP Bypass | May enable | **Disabled** |
| Secrets | Simple | **Strong random** |

### Secrets Management

**Never commit secrets to git:**
```bash
# Add to .gitignore
.env
.env.*
!.env.example
```

**Use secret managers in production:**
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- GCP Secret Manager

**Rotate secrets regularly:**
- JWT secret: Every 90 days
- Encryption keys: Every 180 days
- Admin passwords: Every 60 days

---

## Common Security Scenarios

### Scenario 1: API for Internal Services Only

**Goal:** Restrict API to internal VPN range

```json
{
  "api_name": "internal-orders",
  "api_ip_mode": "whitelist",
  "api_ip_whitelist": ["10.0.0.0/8", "192.168.0.0/16"],
  "api_trust_x_forwarded_for": false
}
```

### Scenario 2: API with Geographic Restrictions

**Goal:** Only allow traffic from specific countries (using Cloudflare)

```json
{
  "trust_x_forwarded_for": true,
  "xff_trusted_proxies": ["173.245.48.0/20", "103.21.244.0/22"],  # Cloudflare IPs
}
```

Then use Cloudflare Firewall Rules or per-API IP lists based on CF-IPCountry header.

### Scenario 3: API for Mobile App

**Goal:** Prevent CSRF, allow CORS from app origin

```json
{
  "api_cors_allow_origins": ["https://app.example.com"],
  "api_cors_allow_credentials": false,  # Use Bearer tokens, not cookies
  "api_cors_allow_methods": ["GET", "POST", "PUT", "DELETE"],
  "api_cors_allow_headers": ["Content-Type", "Authorization"]
}
```

Use `Authorization: Bearer <token>` header instead of cookies to avoid CSRF concerns.

### Scenario 4: High-Security Admin API

**Goal:** Maximum protection for sensitive operations

```bash
# Environment
HTTPS_ONLY=true
CORS_STRICT=true
ALLOWED_ORIGINS=https://admin.example.com  # Single origin only
ALLOW_CREDENTIALS=True

# IP whitelist
{
  "ip_whitelist": ["203.0.113.0/24"],  # Office IP range only
  "trust_x_forwarded_for": false       # Direct connection required
}
```

---

## Security Testing

Doorman includes comprehensive security test coverage:

The Rust suite covers CSRF, HTTPS headers, JWT validation, IP policy, request IDs, and audit behavior.

**Run security tests:**
```bash
cargo test --manifest-path gateway-rs/Cargo.toml --locked
cargo clippy --manifest-path gateway-rs/Cargo.toml --locked --all-targets --all-features -- -D warnings
```

---

## Incident Response

### Suspected Token Compromise

1. Immediately revoke affected tokens:
   ```bash
   POST /platform/authorization/invalidate
   {"username": "affected-user"}
   ```

2. Rotate JWT secret (requires restart):
   ```bash
   # Update JWT_SECRET_KEY in .env
   docker compose up -d --force-recreate doorman
   ```

3. Audit logs for suspicious activity:
   ```bash
   grep "affected-user" logs/doorman-trail.log
   ```

4. Force password reset for affected users

### Suspected IP Spoofing

1. Verify `xff_trusted_proxies` is configured correctly
2. Check `trust_x_forwarded_for` setting
3. Review audit logs for anomalous IPs:
   ```bash
   grep "ip.global_deny" logs/doorman-trail.log
   ```

4. Add malicious IPs to global blacklist

### Elevated Error Rates

1. Check health endpoints:
   ```bash
   GET /platform/monitor/readiness
   ```

2. Review logs for errors:
   ```bash
   tail -f logs/doorman.log | grep ERROR
   ```

3. Check Redis/MongoDB connectivity
4. Verify CORS configuration if preflight failures

---

## Compliance and Standards

Doorman addresses common security frameworks:

**OWASP Top 10:**
- A01: Broken Access Control - RBAC, IP policies, subscriptions
- A02: Cryptographic Failures - TLS, encryption at rest
- A03: Injection - Input validation, request size limits
- A05: Security Misconfiguration - Secure defaults, startup validation
- A07: Identification and Auth Failures - JWT, token revocation, CSRF

**Industry standards:**
- RFC 6797 (HSTS)
- RFC 7519 (JWT)
- CSP Level 3
- CSRF Double Submit Pattern

---

## References

- [Configuration Reference](./02-configuration.md) - Environment variables
- [Operations Guide](./05-operations.md) - Production deployment
- [Tools](./06-tools.md) - CORS checker for diagnostics

For security concerns or questions, review the code or open an issue on GitHub.
