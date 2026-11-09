# Operations Guide (Abridged)

This guide covers production setup, deployment, monitoring, and runbooks.

## Production Environment

Key settings:

```bash
ENV=production
HTTPS_ONLY=true
MEM_OR_EXTERNAL=REDIS
JWT_SECRET_KEY=<strong-secret>
TOKEN_ENCRYPTION_KEY=<strong-secret>
MEM_ENCRYPTION_KEY=<strong-secret>
ALLOWED_ORIGINS=https://admin.yourdomain.com
CORS_STRICT=true
COOKIE_DOMAIN=yourdomain.com
LOG_FORMAT=json
```

## Deployment

- Single instance via Docker Compose
- Multi-instance requires Redis/Mongo and a load balancer
- Sticky sessions recommended (cookie auth)

## Health and Monitoring

- `/api/health` – liveness
- `/platform/monitor/readiness` – readiness. Returns HTTP 200 with `"status": "ready"`, or HTTP 503 with `"status": "degraded"`
- `/platform/monitor/metrics` – aggregated metrics (with manage_gateway perms)

## Reverse Proxy (Nginx Example)

Proxy pass to backend, forward `X-Forwarded-*` headers, and terminate TLS.

## Runbooks

- Clear caches: `DELETE /api/caches`
- Rotate API key: `POST /platform/credit/{group}/rotate`
- Restart gateway: `POST /platform/security/restart`

## Backups, Upgrades and Key Rotation

- **Memory mode:** the dump directory (`MEM_DUMP_PATH`) is the database. Dumps are written on `POST /platform/memory/dump`, on SIGTERM, and on the autosave interval; a hard kill loses changes since the last dump. Back up the whole directory.
- **Shared mode:** back up MongoDB with `mongodump`; Redis holds sessions and counters only.
- **Upgrade:** back up, set `DOORMAN_IMAGE` to the new tag, `docker compose pull doorman && docker compose up -d doorman`. Roll back by setting the previous tag.
- **`JWT_SECRET_KEY`:** rotating signs everyone out; data is untouched.
- **`TOKEN_ENCRYPTION_KEY`:** rotating invalidates every personal AI key (`dk_...`) and stored secrets must be re-entered.
- **`MEM_ENCRYPTION_KEY`:** cannot be rotated in place; a gateway with a different key refuses to start rather than lose data.

The full, tested procedures are in the operations guide (`user-docs/05-operations.md`).
