# Operations Guide

Production deployment, monitoring, and operational runbooks for Doorman API Gateway.

## Overview

This guide covers:
- Production environment configuration
- Deployment strategies
- Health checks and monitoring
- Redis and MongoDB setup
- Operational runbooks
- Graceful restarts and memory management
- Response envelope configuration

---

## Production Environment Configuration

### Required Production Settings

```bash
# Environment
ENV=production

# HTTPS (REQUIRED)
# TLS terminated at reverse proxy (Nginx, Traefik, ALB, etc.)
HTTPS_ONLY=true

# Secrets (REQUIRED - use strong random values)
JWT_SECRET_KEY=<strong-random-secret-32chars+>
TOKEN_ENCRYPTION_KEY=<api-key-encryption-secret-32chars+>
MEM_ENCRYPTION_KEY=<memory-dump-encryption-secret-32chars+>

# CORS (strict configuration)
ALLOWED_ORIGINS=https://admin.yourdomain.com,https://api.yourdomain.com
CORS_STRICT=true
COOKIE_DOMAIN=yourdomain.com
ALLOW_CREDENTIALS=True

# Cache and Database
MEM_OR_EXTERNAL=REDIS    # Use Redis in production
REDIS_HOST=redis.internal
REDIS_PORT=6379
REDIS_DB=0

MONGO_DB_HOSTS=mongo1.internal:27017,mongo2.internal:27017,mongo3.internal:27017
MONGO_REPLICA_SET_NAME=rs0

# Logging
LOG_FORMAT=json          # Structured logs for SIEM
LOG_LEVEL=INFO

# Request limits
MAX_BODY_SIZE_BYTES=1048576        # 1MB default
MAX_BODY_SIZE_BYTES_SOAP=2097152   # 2MB for SOAP

# Response envelopes
STRICT_RESPONSE_ENVELOPE=true      # Consistent API responses

# Security
LOCAL_HOST_IP_BYPASS=false         # Disable localhost bypass
```

### Recommended Defaults

| Setting | Value | Purpose |
|---------|-------|---------|
| `HTTPS_ONLY` | `true` | Set `Secure` flag on cookies and enforce CSRF |
| `CORS_STRICT` | `true` | Disallow wildcard origins with credentials |
| `LOG_FORMAT` | `json` | JSON log output for log pipelines |
| `MAX_BODY_SIZE_BYTES` | `1048576` | Reject requests above 1MB |
| `STRICT_RESPONSE_ENVELOPE` | `true` | Consistent platform API responses |

For memory-mode recovery rehearsal, set `MEM_DUMP_PATH` to a path inside the
mounted persistent data volume (for example, `/app/data/memory_dump.bin`).
Snapshots use timestamped filenames in that directory. Startup uses the saved
security settings file's `dump_path` when present, then selects
the newest matching stem by file modification time and falls back to the
default stem and finally any `.bin` file in the default directory, matching
Python's startup search. It fails closed if the selected snapshot is corrupt.
Use a filename stem such as `/app/data/memory_dump.bin` with timestamped files
beneath the volume to resume the latest state. In contrast, an HTTP restore
request reads the exact supplied filename (or `MEM_DUMP_PATH` if omitted) and
returns 404 if it does not exist; it never substitutes a different backup.
A dump path outside the mounted volume cannot serve as container-replacement
restore evidence.

### JWT and Token Configuration

```bash
# JWT secret (REQUIRED - gateway fails fast if missing)
JWT_SECRET_KEY=<strong-secret-store-in-vault>

# Access token lifetime (default: 30 minutes)
AUTH_EXPIRE_TIME=30
AUTH_EXPIRE_TIME_FREQ=minutes

# Refresh token lifetime (default: 7 days)
AUTH_REFRESH_EXPIRE_TIME=7
AUTH_REFRESH_EXPIRE_FREQ=days

# API key encryption at rest (recommended)
TOKEN_ENCRYPTION_KEY=<encryption-key-32chars+>
```

**Best practices:**
- Store secrets in a secret manager (Vault, AWS Secrets Manager, etc.)
- Rotate `JWT_SECRET_KEY` every 90 days
- Rotate encryption keys every 180 days
- Never commit secrets to version control

---

## Deployment

### Single-Instance Deployment

**Docker Compose:**

```yaml
version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      ENV: production
      HTTPS_ONLY: "true"
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      TOKEN_ENCRYPTION_KEY: ${TOKEN_ENCRYPTION_KEY}
      MEM_ENCRYPTION_KEY: ${MEM_ENCRYPTION_KEY}
      ALLOWED_ORIGINS: https://admin.yourdomain.com
      CORS_STRICT: "true"
      COOKIE_DOMAIN: yourdomain.com
      LOG_FORMAT: json
      MEM_OR_EXTERNAL: REDIS
      REDIS_HOST: redis
      MONGO_DB_HOSTS: mongo:27017
      MONGO_REPLICA_SET_NAME: rs0
    volumes:
      - ./certs:/certs:ro
      - ./logs:/app/logs
    ports:
      - "5001:5001"
    depends_on:
      - redis
      - mongo
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

  mongo:
    image: mongo:7
    command: --replSet rs0 --bind_ip_all
    volumes:
      - mongo-data:/data/db
    restart: unless-stopped

volumes:
  redis-data:
  mongo-data:
```

### Multi-Instance Deployment

**Important:** Memory mode (`MEM_OR_EXTERNAL=MEM`) requires a single worker. For multiple instances or `THREADS>1`, use Redis mode. Startup includes a guard that fails fast when `MEM_OR_EXTERNAL=MEM` and `THREADS>1` to prevent unsafe token revocation and rate limiting semantics across workers.

**Requirements:**
- Redis for shared cache and rate limiting
- MongoDB for persistence
- Load balancer with sticky sessions (for cookie-based auth)

**Example with multiple replicas:**

```yaml
services:
  backend:
    # ... same config as above ...
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G
    environment:
      THREADS: 4  # Workers per instance
      # ... other config ...
```

### Reverse Proxy Deployment

**Nginx example:**

```nginx
upstream doorman_backend {
    server 127.0.0.1:5001;
    # Or multiple instances:
    # server backend1:5001;
    # server backend2:5001;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://doorman_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

**Doorman configuration for proxy:**

```bash
# Backend listens on HTTP but enforces secure behavior
HTTPS_ONLY=true
PORT=5001

# Trust proxy headers
trust_x_forwarded_for=true
xff_trusted_proxies=["10.0.1.10"]  # Nginx IP
```

---

## Redis Setup

### Standalone Redis

```bash
# Docker
docker run -d --name redis \
  -p 6379:6379 \
  -v redis-data:/data \
  redis:7-alpine redis-server --appendonly yes

# Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

### Redis Sentinel (High Availability)

```yaml
# docker-compose.yml
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-master-data:/data

  redis-sentinel:
    image: redis:7-alpine
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./sentinel.conf:/etc/redis/sentinel.conf:ro
    depends_on:
      - redis-master
```

### Redis Cluster

For large-scale deployments:

```bash
# Use Redis Cluster for horizontal scaling
REDIS_HOST=redis-cluster-node1:6379,redis-cluster-node2:6379,redis-cluster-node3:6379
```

---

## MongoDB Setup

### Replica Set (Recommended)

**Initialize replica set:**

```bash
# Start MongoDB
docker run -d --name mongo \
  -p 27017:27017 \
  mongo:7 --replSet rs0 --bind_ip_all

# Initialize replica set
docker exec -it mongo mongosh --eval "rs.initiate({
  _id: 'rs0',
  members: [
    { _id: 0, host: 'mongo:27017' }
  ]
})"

# Verify status
docker exec -it mongo mongosh --eval "rs.status()"
```

**Configuration:**

```bash
MONGO_DB_HOSTS=mongo:27017
MONGO_REPLICA_SET_NAME=rs0
```

### Multi-Node Replica Set (Production)

```yaml
# docker-compose.yml
services:
  mongo1:
    image: mongo:7
    command: --replSet rs0 --bind_ip_all
    volumes:
      - mongo1-data:/data/db

  mongo2:
    image: mongo:7
    command: --replSet rs0 --bind_ip_all
    volumes:
      - mongo2-data:/data/db

  mongo3:
    image: mongo:7
    command: --replSet rs0 --bind_ip_all
    volumes:
      - mongo3-data:/data/db
```

**Initialize:**

```bash
docker exec -it mongo1 mongosh --eval "rs.initiate({
  _id: 'rs0',
  members: [
    { _id: 0, host: 'mongo1:27017' },
    { _id: 1, host: 'mongo2:27017' },
    { _id: 2, host: 'mongo3:27017' }
  ]
})"
```

**Configuration:**

```bash
MONGO_DB_HOSTS=mongo1:27017,mongo2:27017,mongo3:27017
MONGO_REPLICA_SET_NAME=rs0
```

---

## Health Checks and Monitoring

### Health Endpoints

**Liveness Probe** - Basic health check:
```bash
GET /platform/monitor/liveness

# Response:
{"status": "alive"}
```

**Readiness Probe** - Checks dependencies:
```bash
GET /platform/monitor/readiness

# Response:
{
  "status": "ready",
  "mongodb": "connected",
  "redis": "connected"
}
```

Readiness returns HTTP 200 with `"status": "ready"`, or HTTP 503 with
`"status": "degraded"`. It reports degraded when MongoDB or Redis is
unreachable, an active gRPC API has no usable descriptor, or a native TLS
certificate has expired, so a plain HTTP probe takes a degraded instance out of
rotation.
If MongoDB is down, every platform request, including readiness, fails closed with
503. Privileged readiness also returns `mongodb`, `redis`, `mode`,
`missing_grpc_descriptors` and `tls_certificates_valid`. Expired per-token revocations are purged at startup
and every five minutes by default; set
`REVOCATION_PURGE_INTERVAL_SECONDS` only when a different cleanup interval is
required.

**Gateway Status** (public):
```bash
GET /api/health  # public probe

GET /api/status  # detailed (requires manage_gateway)

# Response:
{
  "status": "ok",
  "uptime_seconds": 12345,
  "memory_usage_mb": 256,
  "mode": "redis"
}
```

### Kubernetes Probes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: doorman-backend
spec:
  containers:
  - name: backend
    image: ghcr.io/doorman-dev/doorman:3.2.0
    livenessProbe:
      httpGet:
        path: /platform/monitor/liveness
        port: 5001
      initialDelaySeconds: 10
      periodSeconds: 30
    readinessProbe:
      httpGet:
        path: /platform/monitor/readiness
        port: 5001
      initialDelaySeconds: 5
      periodSeconds: 10
```

### Metrics Endpoint

**Requires authentication + `manage_gateway` permission:**

```bash
GET /platform/monitor/metrics?range=24h

# Response:
{
  "period": "24h",
  "total_requests": 125000,
  "total_errors": 250,
  "error_rate": 0.002,
  "avg_response_time_ms": 45,
  "p50_response_time_ms": 35,
  "p95_response_time_ms": 120,
  "p99_response_time_ms": 250,
  "apis": {
    "customers/v1": {
      "requests": 50000,
      "errors": 100,
      "avg_response_time_ms": 40
    }
  }
}
```

**Prometheus integration:**

Export metrics to Prometheus for alerting and dashboards:

```python
# Add Prometheus exporter middleware (future enhancement)
# Metrics: request_count, request_duration, error_count, credit_usage
```

---

## Logging

### Log Files

- **Main log:** `logs/doorman.log`
- **Audit trail:** `logs/doorman-trail.log`

### Log Formats

**Plain text (development):**
```
2024-01-15 10:30:00 INFO [request_id=abc123] User admin logged in
```

**JSON (production):**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "request_id": "abc123",
  "message": "User admin logged in",
  "username": "admin",
  "client_ip": "192.168.1.100"
}
```

**Configuration:**
```bash
LOG_FORMAT=json
LOG_LEVEL=INFO
```

### Log Shipping

**Fluentd example:**

```yaml
# fluentd.conf
<source>
  @type tail
  path /app/logs/doorman*.log
  pos_file /var/log/td-agent/doorman.pos
  tag doorman.*
  <parse>
    @type json
    time_key timestamp
    time_format %Y-%m-%dT%H:%M:%SZ
  </parse>
</source>

<match doorman.**>
  @type elasticsearch
  host elasticsearch.internal
  port 9200
  index_name doorman
  type_name _doc
</match>
```

---

## Memory Management

### Memory Mode

**When to use:**
- Development and testing
- Single-instance deployments
- Small workloads

**Configuration:**
```bash
MEM_OR_EXTERNAL=MEM
MEM_ENCRYPTION_KEY=<32-char-secret>
MEM_DUMP_PATH=data/memory_dump.bin
THREADS=1  # REQUIRED - only 1 worker in memory mode
```

**Memory dumps:**
- Written on graceful shutdown
- Can be triggered manually with `POST /platform/memory/dump` or `SIGUSR1`
- Encrypted with `MEM_ENCRYPTION_KEY`
- Restored automatically on startup
- A corrupt, unauthenticated, or unsupported snapshot stops startup rather than
  silently starting with empty state; a missing snapshot is treated as first boot

**Autosave runtime configuration:**
```bash
PUT /platform/security/settings
{
  "enable_auto_save": true
}
```

This persists the preference and immediately reconfigures the in-process
autosave worker. `auto_save_frequency_seconds` must be at least 60; an enabled
worker without `MEM_ENCRYPTION_KEY` is marked unhealthy until corrected.

### Redis Mode

**When to use:**
- Production deployments
- Multi-instance setups
- High traffic workloads

**Configuration:**
```bash
MEM_OR_EXTERNAL=REDIS
REDIS_HOST=redis.internal
REDIS_PORT=6379
REDIS_DB=0
THREADS=4  # Can use multiple workers
```

**Benefits:**
- Distributed rate limiting
- Shared cache across instances
- No state divergence between workers

---

## Operational Runbooks

### Runbook 1: Graceful Restart

**Goal:** Restart gateway with zero downtime.

**Steps:**

1. **Verify health:**
   ```bash
   curl https://api.yourdomain.com/platform/monitor/readiness
   ```

2. **Trigger memory dump (if memory mode):**
   ```bash
   docker compose stop  # Writes dump automatically
   ```

3. **Restart service:**
   ```bash
   # Docker Compose
   docker compose restart backend

   # Systemd
   sudo systemctl restart doorman

   # Direct
   docker compose up -d
   ```

4. **Verify startup:**
   ```bash
   tail -f logs/doorman.log
   # Look for: "Application startup complete"
   ```

5. **Check health:**
   ```bash
   curl https://api.yourdomain.com/platform/monitor/readiness
   ```

### Runbook 2: Token Compromise Response

**Goal:** Revoke compromised tokens and secure system.

**Steps:**

1. **Identify affected user:**
   ```bash
   grep "suspicious-activity" logs/doorman-trail.log
   ```

2. **Revoke user's tokens:**
   ```bash
   POST /platform/authorization/invalidate
   {"username": "affected-user"}
   ```

3. **Force password reset:**
   ```bash
   PUT /platform/user/affected-user
   {"force_password_reset": true}
   ```

4. **Audit recent activity:**
   ```bash
   grep "affected-user" logs/doorman-trail.log | tail -100
   ```

5. **If widespread compromise, rotate JWT secret:**
   ```bash
   # Update .env with new JWT_SECRET_KEY
   # Restart gateway (invalidates all tokens)
   docker compose restart backend
   ```

### Runbook 3: Elevated Error Rates

**Goal:** Diagnose and resolve high error rates.

**Steps:**

1. **Check health endpoints:**
   ```bash
   curl https://api.yourdomain.com/platform/monitor/readiness
   ```

2. **Review recent errors:**
   ```bash
   tail -100 logs/doorman.log | grep ERROR
   ```

3. **Check Redis connectivity:**
   ```bash
   redis-cli -h redis.internal ping
   ```

4. **Check MongoDB connectivity:**
   ```bash
   mongosh --host mongo.internal --eval "db.adminCommand('ping')"
   ```

5. **Review metrics:**
   ```bash
   curl -b cookies.txt https://api.yourdomain.com/platform/monitor/metrics?range=1h
   ```

6. **Common fixes:**
   - Restart Redis if connection errors
   - Restart MongoDB if replica set issues
   - Scale up instances if overloaded
   - Check upstream service health

### Runbook 4: CORS Configuration Issues

**Goal:** Fix CORS preflight failures.

**Steps:**

1. **Use CORS checker:**
   ```bash
   POST /platform/tools/cors/check
   {
     "origin": "https://app.example.com",
     "method": "POST",
     "request_headers": ["Content-Type", "Authorization"],
     "with_credentials": true
   }
   ```

2. **Review effective config:**
   ```bash
   # Check environment variables
   echo $ALLOWED_ORIGINS
   echo $CORS_STRICT
   ```

3. **Common fixes:**
   - Add origin to `ALLOWED_ORIGINS`
   - Set `CORS_STRICT=true` to reject wildcard with credentials
   - Ensure `ALLOW_CREDENTIALS=true` if using cookies
   - Verify `COOKIE_DOMAIN` matches origin hostname

4. **Restart to apply changes:**
   ```bash
   docker compose restart backend
   ```

### Runbook 5: CSRF Validation Failures

**Goal:** Fix CSRF token errors.

**Steps:**

1. **Verify HTTPS config:**
   ```bash
   echo $HTTPS_ONLY
   # Must be true for CSRF
   ```

2. **Check client implementation:**
   - Ensure client reads `csrf_token` cookie
   - Verify `X-CSRF-Token` header is sent
   - Confirm header value matches cookie

3. **Test with curl:**
   ```bash
   # Login and get CSRF token
   curl -c cookies.txt -s \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@example.com","password":"..."}' \
     https://api.example.com/platform/authorization

   # Extract CSRF token
   CSRF_TOKEN=$(grep csrf_token cookies.txt | awk '{print $7}')

   # Use in request
   curl -b cookies.txt \
     -H "X-CSRF-Token: $CSRF_TOKEN" \
     -H 'Content-Type: application/json' \
     -X POST https://api.example.com/platform/api -d '{...}'
   ```

4. **Common fixes:**
   - Enable HTTPS if not already
   - Ensure `COOKIE_DOMAIN` is correct
   - Check that cookies are not blocked by browser

---

## Response Envelope Configuration

### Strict Response Envelope

When `STRICT_RESPONSE_ENVELOPE=true`, platform endpoints return consistent structure:

**Success (200):**
```json
{
  "status_code": 200,
  "response": {
    "api_name": "customers",
    "api_version": "v1"
  }
}
```

**Created (201):**
```json
{
  "status_code": 201,
  "message": "Resource created successfully"
}
```

**Error (400/403/404):**
```json
{
  "status_code": 403,
  "error_code": "ROLE009",
  "error_message": "You do not have permission to create roles"
}
```

**Gateway responses (`/api/*`):**
- Not wrapped by default
- Return upstream response as-is
- Can be enabled per-API if needed

**When to enable:**
- Client expects consistent envelope
- Standardized error handling
- API versioning and evolution

**When to disable:**
- Clients expect raw upstream responses

---

## SLI Dashboard and Alerts (Prometheus/Grafana)

Starter assets are included:

- `ops/grafana-dashboard.json` — Grafana dashboard panels for:
  - p95 latency (ms)
  - Error rate
  - Upstream timeout rate
  - Retry rate

- `ops/alerts-prometheus.yml` — Prometheus alert rules:
  - High p95 latency (> 250ms for 10m)
  - High error rate (> 1% for 10m)
  - Upstream timeout spike
  - Elevated retry rate

Import and tune thresholds to match your SLOs.

## Load Testing with k6

Use `load-tests/k6/load.test.js` to validate performance and SLOs in CI:

```bash
k6 run load-tests/k6/load.test.js \
  -e BASE_URL=http://localhost:3001 \
  -e RPS=50 \
  -e DURATION=2m \
  -e REST_PATHS='["/api/rest/health"]' \
  -e PLATFORM_PATHS='["/platform/authorization/status"]'
```

Thresholds embedded in the script will fail the run if unmet. A JUnit report (`junit.xml`) is emitted for CI.

## Logging Redaction

Gateway activity logs intentionally omit request headers and bodies. Structured
management-audit callers use the gateway redaction helper, which masks
Authorization/Proxy-Authorization, Cookie/Set-Cookie, API-key, password,
secret, token, and credential fields before an event is emitted. Do not add
raw request headers, bodies, or secret-bearing configuration values to log
fields; use the redaction helper when a diagnostic field is necessary. IP-denial
events record only the parsed effective and direct IP addresses, never the raw
forwarded-header value.

## Pagination Defaults and Caps

Server‑side pagination is enforced across list endpoints.

```bash
# Maximum page size (default 100 if unset)
MAX_PAGE_SIZE=100

# Clients should pass page & page_size explicitly, e.g., /platform/role/all?page=1&page_size=50
```

- Maximum compatibility
- Minimal overhead

---

## Backup, Recovery, Upgrades and Key Rotation

Every procedure in this section was run against a real gateway (memory mode, and
MongoDB 7 + Redis 7 for shared mode) on 8 November 2026. The results quoted are
what happened, not what is expected.

### Where state lives

| Storage mode | Durable state | Lost if this goes away |
| --- | --- | --- |
| Memory (`MEM_OR_EXTERNAL=MEM`) | Encrypted dump files in the directory of `MEM_DUMP_PATH`, plus `SECURITY_SETTINGS_FILE` | Everything since the last dump if the process is killed without SIGTERM |
| Shared (`MEM_OR_EXTERNAL=REDIS`) | MongoDB: APIs, users, groups, roles, credentials, AI settings, keys, usage | Redis holds sessions, rate-limit and budget counters, revocations and caches. Losing Redis signs people out and resets short-lived counters; configuration is safe |

In memory mode the dump directory **is** the database. Put it on a persistent
volume and back that volume up.

### Memory mode: backup and restore

A dump is written:

- on demand, with `POST /platform/memory/dump` (needs `manage_security`);
- on SIGTERM or SIGINT, after in-flight requests drain (`docker stop` sends SIGTERM);
- on SIGUSR1, without stopping;
- every `MEM_AUTO_SAVE_FREQ` seconds when `MEM_AUTO_SAVE_ENABLED=true`.

Each dump is a new timestamped file, for example `dump-20261108T205822Z.bin`,
in the directory of `MEM_DUMP_PATH`. On start the gateway loads the newest one.

```bash
# Take a dump now (cookie from POST /platform/authorization)
curl -s -b cookies -H "x-csrf-token: $CSRF" -X POST \
  http://127.0.0.1:3001/platform/memory/dump
# {"response":{"path":"/data/dump-20261108T205822Z.bin"}}

# Back up: copy the whole dump directory and the settings file off the host
docker run --rm -v doorman-data:/data -v "$PWD":/backup alpine:3.20 \
  tar czf /backup/doorman-$(date +%Y%m%d%H%M).tgz -C /data .

# Restore: stop the gateway, put the files back, start it with the same MEM_ENCRYPTION_KEY
docker compose stop doorman
docker run --rm -v doorman-data:/data -v "$PWD":/backup alpine:3.20 \
  sh -c 'rm -f /data/dump-*.bin && tar xzf /backup/doorman-202611082100.tgz -C /data'
docker compose start doorman
```

What the test showed:

| Step | Result |
| --- | --- |
| Create an API, `docker stop` (SIGTERM), start again | API present. The final dump on shutdown included it |
| Create an API, `docker kill -s KILL`, start again | That API was **gone**: only the last dump survives a hard kill |
| Start with a different `MEM_ENCRYPTION_KEY` | Refused to start: `memory snapshot restore failed; refusing to start with empty state`. Dump files unchanged (same SHA-256) |

To bound what a crash can lose, set `MEM_AUTO_SAVE_ENABLED=true` and a
`MEM_AUTO_SAVE_FREQ` you can live with (minimum 60 seconds).

### Shared mode: backup and restore

Back up MongoDB. Redis does not need a backup for recovery.

```bash
# Backup (one compressed archive per database)
mongodump --uri "mongodb://USER:PASS@mongo:27017/?authSource=admin" \
  --db doorman --archive=/backups/doorman-$(date +%Y%m%d%H%M).archive --gzip

# Restore (replaces the collections in the archive), then restart the gateways
mongorestore --uri "mongodb://USER:PASS@mongo:27017/?authSource=admin" \
  --archive=/backups/doorman-202611082100.archive --gzip --drop
docker compose restart doorman
```

Tested: an API created before the dump was present after dropping the database,
restoring and restarting; an API created after the dump was not, as expected.
`--drop` makes the restore exact, so anything created after the backup is lost.
Take a fresh dump right before an upgrade.

### Upgrade and rollback

Doorman images are published as `ghcr.io/doorman-dev/doorman:<version>`, and
`docker-compose.yml` pins one through `DOORMAN_IMAGE`.

```bash
# 1. Back up first (dump directory, or mongodump)
# 2. Point at the new version and pull it
export DOORMAN_IMAGE=ghcr.io/doorman-dev/doorman:3.0.2
docker compose pull doorman
# 3. Replace the container (SIGTERM, so memory mode writes its final dump first)
docker compose up -d doorman
# 4. Check
curl -s http://127.0.0.1:3001/platform/monitor/liveness
curl -s http://127.0.0.1:3001/platform/monitor/readiness   # body must say "ready"

# Roll back: same steps with the previous tag. If the new version changed stored
# data in a way the old one cannot read, restore the backup from step 1 first.
export DOORMAN_IMAGE=ghcr.io/doorman-dev/doorman:3.2.0
docker compose up -d doorman
```

Read the release notes before upgrading; they call out anything that needs action,
such as a new required setting. Managed tenants started by `doorman-wrapper` are
upgraded one at a time from the operator console's **Versions** page, which
swaps the container and puts the old one back if the new one fails its health
check. Upgrade one test tenant first.

### Key rotation

| Key | What rotating it does | Procedure |
| --- | --- | --- |
| `JWT_SECRET_KEY` | Every session and access token stops working; data is untouched | Change it and restart. Everyone signs in again |
| `DOORMAN_ADMIN_PASSWORD` | Only used to create the first admin; an existing admin keeps their password (test `bootstrap_admin_seed_matches_python_and_preserves_existing_credentials`) | Change the password in **Settings** instead |
| Provider API keys | None for users | Edit the provider credential in **AI Gateway → Providers**. Requests use the new key at once |
| `TOKEN_ENCRYPTION_KEY` | **Every personal AI key (`dk_...`) stops working** (tested), and stored secrets encrypted with the old key can no longer be read (from the code: there is no re-encryption step) | Plan it: set the new key, restart, re-enter every provider key and API credential, and ask everyone to create a new AI key in **My AI** |
| `MEM_ENCRYPTION_KEY` | The gateway cannot read its existing dumps and will not start. In memory mode without `TOKEN_ENCRYPTION_KEY` it is also the key material for secrets and `dk_` keys | No in-place rotation. Treat it as permanent for the lifetime of the data, or move to shared mode |

Tested on a running gateway:

| Step | Result |
| --- | --- |
| Old session cookie after changing `JWT_SECRET_KEY` | `401 GTW998 Unauthorized`; a fresh login worked and all data was present |
| A `dk_` key after a plain restart | `200`, still valid |
| The same `dk_` key after adding `TOKEN_ENCRYPTION_KEY` | `401 AI007 Invalid AI access key`; admin login unaffected |

For `MEM_ENCRYPTION_KEY`, `/platform/config/export/all` and `/platform/config/import`
carry APIs, endpoints, groups, roles and routings across to a gateway with a new
key, but **not** users, credentials, AI settings or keys. Those must be recreated.

### Degraded-mode behaviour

Tested with MongoDB 7 and Redis 7, by stopping each container while the gateway ran:

| Outage | Liveness | Readiness | Platform API | Recovery |
| --- | --- | --- | --- | --- |
| Redis down | 200 | 503 with `"status": "degraded"` | Reads with an existing session worked; sign-in returned 503 | Automatic when Redis returned |
| MongoDB down | 503 | 503 | Every request returned `503 SEC012 Security policy is temporarily unavailable` (fails closed) | Automatic: reads, writes and sign-in worked once MongoDB returned |
| Upstream API or AI provider down | 200 | 200 | Only that route fails. AI fallback targets take over when configured; a provider 429 is passed through, never moved to a backup (covered by the AI gateway tests, not by this run) | Automatic |

During a Redis outage readiness returns 503, so a readiness probe takes the
instance out of rotation even though reads still work. Alert on readiness or on
failed sign-ins.

---

## Performance Tuning

### Worker Threads

```bash
# Default: 4 workers
THREADS=4

# Memory mode: MUST be 1
THREADS=1

# High traffic: 8-16 workers
THREADS=8
```

### Connection Pooling

Upstream connections are pooled automatically. No configuration needed.

### Request Limits

```bash
# Balance security and usability
MAX_BODY_SIZE_BYTES=1048576         # 1MB for most APIs
MAX_BODY_SIZE_BYTES_SOAP=2097152    # 2MB for large SOAP envelopes
MAX_MULTIPART_SIZE_BYTES=10485760   # 10MB for file uploads
```

### Caching

**Redis caching:**
- Rate limit state
- Token blacklist
- Session data

**TTLs:**
- Access tokens: 30 minutes (configurable)
- Refresh tokens: 7 days (configurable)
- Rate limit windows: 1 minute to 1 day

---

## Production Checklist

Before going live:

- [ ] `ENV=production` set
- [ ] HTTPS enabled (`HTTPS_ONLY=true`)
- [ ] Valid TLS certificates configured
- [ ] Strong `JWT_SECRET_KEY` set
- [ ] `TOKEN_ENCRYPTION_KEY` and `MEM_ENCRYPTION_KEY` configured
- [ ] `ALLOWED_ORIGINS` set to explicit domains
- [ ] `CORS_STRICT=true`
- [ ] `COOKIE_DOMAIN` matches your domain
- [ ] Redis configured and tested
- [ ] MongoDB replica set configured
- [ ] `LOG_FORMAT=json` enabled
- [ ] Log shipping to SIEM configured
- [ ] Health checks configured in load balancer
- [ ] Metrics monitoring set up
- [ ] Backup strategy defined
- [ ] Runbooks documented for your team
- [ ] Admin password rotated
- [ ] Least-privilege users created
- [ ] IP whitelisting configured (if needed)
- [ ] Rate limits tested
- [ ] Load testing completed

---

## Support and Troubleshooting

**Documentation:**
- [Configuration Reference](./02-configuration.md)
- [Security Guide](./03-security.md)
- [API Workflows](./04-api-workflows.md)
- [Tools](./06-tools.md)

**Logs to check:**
- `logs/doorman.log` - Application log
- `logs/doorman-trail.log` - Audit trail

**Common issues:**
- Review the [API Workflows - Troubleshooting](./04-api-workflows.md#common-errors-and-troubleshooting) section
- Use the CORS checker tool for CORS issues
- Check health endpoints for dependency problems
### Request ID Propagation

- Every request carries a `X-Request-ID` for end‑to‑end tracing.
- Doorman forwards `X-Request-ID` to upstreams and echoes it back in responses.
- If an upstream echoes its own header (e.g., `X-Upstream-Request-ID`), add it to your API’s `api_allowed_headers` so the gateway exposes it back to clients.

### HTTP Resilience & Backoff

- Upstream calls use jittered exponential backoff and a simple circuit breaker.
- Tune via environment variables (see Configuration → HTTP Resilience).
- Use per‑API retry count (`api_allowed_retry_count`) to control retry behavior.
