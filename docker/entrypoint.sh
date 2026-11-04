#!/usr/bin/env bash
set -euo pipefail

_apply_env_file_no_override() {
  local file="$1"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    line=${line#export }
    if printf '%s' "$line" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*='; then
      key="${line%%=*}"
      val="${line#*=}"
      if [ "${val#\"}" != "$val" ] && [ "${val%\"}" != "$val" ]; then
        val="${val#\"}"; val="${val%\"}"
      elif [ "${val#\'}" != "$val" ] && [ "${val%\'}" != "$val" ]; then
        val="${val#\'}"; val="${val%\'}"
      fi
      if [ -z "${!key+x}" ]; then
        export "$key=$val"
      fi
    fi
  done < "$file"
}

for dir in /env /app/web-client /app; do
  if [ -d "$dir" ]; then
    for file in "$dir"/.env* "$dir"/*.env; do
      if [ -f "$file" ] && ! printf '%s' "$file" | grep -qE '\.example$'; then
        echo "[entrypoint] Loading env file: $file"
        _apply_env_file_no_override "$file"
      fi
    done
  fi
done

_ensure_writable_directory() {
  local target="$1"
  local fallback="$2"
  local env_var="$3"

  mkdir -p "$target" 2>/dev/null || true
  local probe="$target/.write_probe_$$"
  if touch "$probe" 2>/dev/null; then
    rm -f "$probe" 2>/dev/null || true
  else
    echo "[entrypoint] WARNING: Directory '$target' is not writable by user $(id -un 2>/dev/null || id -u) (UID $(id -u))."
    echo "[entrypoint] WARNING: If upgrading from an older Doorman release, fix volume ownership:"
    echo "[entrypoint] WARNING:   docker run --rm -v <volume-name>:/v alpine chown -R 10001:10001 /v"
    if [ -n "$fallback" ]; then
      echo "[entrypoint] Falling back $env_var to '$fallback' for this container session."
      mkdir -p "$fallback" 2>/dev/null || true
      export "$env_var=$fallback"
    fi
  fi
}

_ensure_writable_directory "${LOGS_DIR:-/app/logs}" "/tmp/logs" "LOGS_DIR"

if ! touch /app/data/.write_probe_$$ 2>/dev/null; then
  echo "[entrypoint] WARNING: Directory '/app/data' is not writable by user $(id -un 2>/dev/null || id -u) (UID $(id -u))."
  mkdir -p /tmp/data 2>/dev/null || true
  if [ "${MEM_DUMP_PATH:-}" = "/app/data/memory_dump.bin" ]; then
    echo "[entrypoint] Falling back MEM_DUMP_PATH to '/tmp/data/memory_dump.bin'."
    export MEM_DUMP_PATH="/tmp/data/memory_dump.bin"
  fi
  if [ "${SECURITY_SETTINGS_FILE:-}" = "/app/data/security_settings.json" ]; then
    echo "[entrypoint] Falling back SECURITY_SETTINGS_FILE to '/tmp/data/security_settings.json'."
    export SECURITY_SETTINGS_FILE="/tmp/data/security_settings.json"
  fi
else
  rm -f /app/data/.write_probe_$$ 2>/dev/null || true
fi

stop_pid() {
  local pid="${1:-}"
  if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || true; fi
}

graceful_stop() {
  trap - SIGTERM SIGINT
  echo "[entrypoint] Stopping services..."
  stop_pid "${RUST_PID:-}"
  stop_pid "${WEB_PID:-}"
  wait "${RUST_PID:-}" 2>/dev/null || true
  wait "${WEB_PID:-}" 2>/dev/null || true
  exit 0
}
trap graceful_stop SIGTERM SIGINT

echo "[entrypoint] Starting Rust backend on 0.0.0.0:${PORT:-3001}..."
env PORT="${PORT:-3001}" /usr/local/bin/doorman-gateway &
RUST_PID=$!

echo "[entrypoint] Starting Next.js web client on 0.0.0.0:${WEB_PORT:-3000}..."
(
  cd /app/web-client
  exec env PORT="${WEB_PORT:-3000}" npm run start -- -H "${WEB_HOST:-0.0.0.0}" -p "${WEB_PORT:-3000}"
) &
WEB_PID=$!

echo "[entrypoint] Services launched. Rust PID=$RUST_PID Web PID=$WEB_PID"

if [ "${DEMO_SEED:-false}" = "true" ]; then
  (
    set +e
    base="http://localhost:${PORT:-3001}"
    for _ in $(seq 1 40); do
      if curl -sf --connect-timeout 2 --max-time 5 "$base/platform/monitor/liveness" >/dev/null 2>&1; then break; fi
      sleep 1
    done
    cookie_file="/tmp/doorman.demo.cookies"
    if curl -sc "$cookie_file" --connect-timeout 5 --max-time 15 -H 'Content-Type: application/json' \
      -d "{\"email\":\"${DOORMAN_ADMIN_EMAIL:-admin@doorman.dev}\",\"password\":\"${DOORMAN_ADMIN_PASSWORD:-change-me}\"}" \
      "$base/platform/authorization" >/dev/null 2>&1; then
      if curl -sb "$cookie_file" --connect-timeout 5 --max-time 300 -X POST "$base/platform/demo/seed" >/dev/null 2>&1; then
        echo "[entrypoint] Demo seeding completed successfully"
      else
        echo "[entrypoint] Demo seeding failed (HTTP POST /platform/demo/seed returned error)"
      fi
    else
      echo "[entrypoint] Demo seed skipped (login failed)"
    fi
    rm -f "$cookie_file" 2>/dev/null || true
    echo "[entrypoint] All services running and ready for traffic:"
    echo "[entrypoint]   - Web Client: http://localhost:${WEB_PORT:-3000}"
    echo "[entrypoint]   - Gateway API: http://localhost:${PORT:-3001}"
  ) &
fi

wait "$RUST_PID" "$WEB_PID" || true
graceful_stop
