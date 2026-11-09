# Getting Started

## Prerequisites

- Docker and Docker Compose, or Rust 1.88 and Node 20+
- Optional: Redis and MongoDB (production)

## Quick Start

```bash
git clone https://github.com/doorman-dev/doorman.git
cd doorman

# Copy and edit .env
cp .env.example .env
# Set: DOORMAN_ADMIN_EMAIL, DOORMAN_ADMIN_PASSWORD, JWT_SECRET_KEY

# Start (pulls the published image, ghcr.io/doorman-dev/doorman)
docker compose up -d
```

**Access:** Backend `http://localhost:3001`, Web UI `http://localhost:3000`

To build from source instead, run `DOORMAN_IMAGE=doorman:dev docker compose up -d --build`.

## Your first AI request

The demo stack includes a keyless local model, so you can try the AI gateway before
connecting a provider:

```bash
cp .env.demo .env
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d
./scripts/demo-ai-walkthrough.sh
```

The script signs in as the demo admin, creates a team with a 3-request allowance, adds an
employee who creates a personal AI key, and sends 4 requests. The 4th is blocked with
`AI004`. Then it prints the usage. To call the model yourself, sign in at
`http://localhost:3000` as `demo@doorman.dev` / `DemoPassword123!`, create a key under
**My AI**, and run:

```bash
curl http://127.0.0.1:3001/api/ai/demo-local-llm/v1/v1/chat/completions \
  -H "Authorization: Bearer dk_..." -H "Content-Type: application/json" \
  -d '{"model":"llama-demo","messages":[{"role":"user","content":"Hello"}]}'
```

To connect OpenAI, Anthropic, Gemini or Azure OpenAI with your own key, see
/docs/ai-gateway.md.

## Environment Variables

Minimal `.env` configuration:

```bash
# Required
DOORMAN_ADMIN_EMAIL=admin@example.com
DOORMAN_ADMIN_PASSWORD=YourStrongPassword123!
JWT_SECRET_KEY=change-this-to-a-strong-secret-key

# Mode
MEM_OR_EXTERNAL=MEM  # MEM for dev, REDIS for production
THREADS=1  # Must be 1 in MEM mode

# Optional (production)
HTTPS_ONLY=true
REDIS_HOST=localhost
MONGO_DB_HOSTS=localhost:27017
```

See /docs/configuration.md for all options.

## First Login

```bash
export BASE=http://localhost:3001
export COOKIE=/tmp/doorman.cookies

# Login
curl -sc "$COOKIE" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$DOORMAN_ADMIN_EMAIL\",\"password\":\"$DOORMAN_ADMIN_PASSWORD\"}" \
  "$BASE/platform/authorization"
```

Or use Web UI at `http://localhost:3000`

## Your First API

### 1. Create Token Group

```bash
curl -sb "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/credit" \
  -d '{
    "api_credit_group": "demo-api",
    "api_key": "demo-secret-key-123",
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
curl -sb "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/api" \
  -d '{
    "api_name": "demo",
    "api_version": "v1",
    "api_description": "Demo API for testing",
    "api_allowed_roles": ["admin"],
    "api_allowed_groups": ["ALL"],
    "api_servers": ["http://httpbin.org"],
    "api_type": "REST",
    "api_allowed_retry_count": 0,
    "api_allowed_headers": ["content-type", "accept"],
    "api_credits_enabled": true,
    "api_credit_group": "demo-api"
  }'
```

### 3. Add Endpoints

```bash
curl -sb "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint" \
  -d '{
    "api_name": "demo",
    "api_version": "v1",
    "endpoint_method": "GET",
    "endpoint_uri": "/get",
    "endpoint_description": "Echo GET request"
  }'

curl -sb "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/endpoint" \
  -d '{
    "api_name": "demo",
    "api_version": "v1",
    "endpoint_method": "POST",
    "endpoint_uri": "/post",
    "endpoint_description": "Echo POST request"
  }'
```

### 4. Subscribe User

```bash
curl -sb "$COOKIE" -H 'Content-Type: application/json' -X POST \
  "$BASE/platform/subscription/subscribe" \
  -d '{
    "username": "admin",
    "api_name": "demo",
    "api_version": "v1"
  }'
```

### 5. Test

```bash
curl -sb "$COOKIE" "$BASE/api/rest/demo/v1/get?test=123"
```

## Next Steps

- /docs/configuration.md - All environment variables
- /docs/security.md - Production hardening
- /docs/using-fields.html - UI field reference

---

## Production Setup

### .env Configuration

```bash
ENV=production
HTTPS_ONLY=true
MEM_OR_EXTERNAL=REDIS

# Strong secrets (required)
JWT_SECRET_KEY=<strong-random-secret-32-chars>
TOKEN_ENCRYPTION_KEY=<strong-random-secret>
MEM_ENCRYPTION_KEY=<strong-random-secret>

# CORS
ALLOWED_ORIGINS=https://yourdomain.com
CORS_STRICT=true
COOKIE_DOMAIN=yourdomain.com

# Redis/MongoDB
REDIS_HOST=redis
MONGO_DB_HOSTS=mongo:27017
```

### Start with Redis/MongoDB

```bash
docker compose --profile production up -d
```

### Checklist

- [ ] `ENV=production` and `HTTPS_ONLY=true`
- [ ] Change all default secrets
- [ ] Set `CORS_STRICT=true` with explicit origins
- [ ] TLS at reverse proxy (Nginx/Traefik/ALB)
- [ ] Change admin password after first login

See /docs/security.md for full hardening details
