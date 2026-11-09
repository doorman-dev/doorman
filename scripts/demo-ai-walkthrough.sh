#!/usr/bin/env bash
# AI demo walkthrough against a running demo stack:
#   docker compose -f docker-compose.yml -f docker-compose.demo.yml up
#
# 1. Admin creates a team and gives it an AI allowance of 3 requests a month.
# 2. Admin adds an employee to the team and grants access to the local model.
# 3. The employee creates their own AI key and sends requests.
# 4. Usage shows up, and the 4th request is blocked with AI004.
# 5. Bonus: the same gateway also serves a regular REST API.
#
# Needs curl and python3. Safe to re-run: it resets the team allowance first.
set -euo pipefail

BASE="${DOORMAN_URL:-http://127.0.0.1:3001}"
ADMIN_EMAIL="${DOORMAN_ADMIN_EMAIL:-demo@doorman.dev}"
ADMIN_PASSWORD="${DOORMAN_ADMIN_PASSWORD:-DemoPassword123!}"
TEAM="ai-pilot"
EMPLOYEE="dana"
EMPLOYEE_EMAIL="dana@example.com"
EMPLOYEE_PASSWORD="DemoEmployee123!"
API="demo-local-llm"
MODEL="llama-demo"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

# call JAR METHOD PATH [JSON] -> prints body, sets $status
call() {
  local jar="$1" method="$2" path="$3" data="${4:-}"
  local csrf
  csrf="$(awk '$6 == "csrf_token" {print $7}' "$jar" 2>/dev/null || true)"
  local args=(-s -o "$work/body" -w '%{http_code}' -X "$method" -b "$jar" -c "$jar"
    -H "x-csrf-token: $csrf" "$BASE$path")
  [ -n "$data" ] && args+=(-H 'content-type: application/json' -d "$data")
  status="$(curl "${args[@]}")"
  cat "$work/body"
}

login() {
  local jar="$1" email="$2" password="$3"
  call "$jar" POST /platform/authorization "{\"email\":\"$email\",\"password\":\"$password\"}" >/dev/null
  [ "$status" = 200 ] || { echo "login failed for $email ($status)"; cat "$work/body"; exit 1; }
}

chat() {
  curl -s -o "$work/chat" -w '%{http_code}' "$BASE/api/ai/$API/v1/v1/chat/completions" \
    -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Summarise our Q3 API usage\"}]}"
}

admin="$work/admin.jar"
employee="$work/employee.jar"

step "Waiting for the demo stack"
for _ in $(seq 1 60); do
  curl -sf "$BASE/platform/monitor/liveness" >/dev/null 2>&1 && break
  sleep 2
done

step "Admin signs in ($ADMIN_EMAIL)"
login "$admin" "$ADMIN_EMAIL" "$ADMIN_PASSWORD"
echo "ok"

# The demo seeds its data in the background after start-up, which can take a minute.
seeded() {
  call "$admin" GET "/platform/api/$API/v1" >/dev/null
  [ "$status" = 200 ]
}
if ! seeded; then
  printf 'waiting for the demo seed to add %s' "$API"
  for _ in $(seq 1 90); do
    seeded && break
    printf '.'
    sleep 2
  done
  echo
  seeded || { echo "$API was not seeded. Check: docker logs doorman-demo | grep entrypoint"; exit 1; }
fi

step "Admin creates team '$TEAM' and employee '$EMPLOYEE'"
call "$admin" POST /platform/group "{\"group_name\":\"$TEAM\",\"group_description\":\"AI pilot team\",\"api_access\":[\"$API/v1\"]}" >/dev/null
echo "team: HTTP $status (400 means it already exists)"
call "$admin" POST /platform/user "{\"username\":\"$EMPLOYEE\",\"email\":\"$EMPLOYEE_EMAIL\",\"password\":\"$EMPLOYEE_PASSWORD\",\"role\":\"viewer\",\"groups\":[\"ALL\",\"$TEAM\"],\"ui_access\":true}" >/dev/null
echo "employee: HTTP $status (400 means they already exist)"
call "$admin" POST /platform/subscription/subscribe "{\"username\":\"$EMPLOYEE\",\"api_name\":\"$API\",\"api_version\":\"v1\"}" >/dev/null
echo "access to $API/v1: HTTP $status"

step "Admin gives the team an allowance of 3 requests a month"
for id in $(call "$admin" GET /platform/ai/budgets | json "' '.join(b['budget_id'] for b in (d.get('budgets') or d.get('response',{}).get('budgets') or []) if b.get('target')=='$TEAM')"); do
  call "$admin" DELETE "/platform/ai/budgets/$id" >/dev/null
done
call "$admin" POST /platform/ai/budgets "{\"name\":\"AI pilot team allowance\",\"scope\":\"group\",\"target\":\"$TEAM\",\"period\":\"month\",\"limit_type\":\"requests\",\"limit_value\":3,\"action\":\"block\"}" | json "d.get('budget_id') or d"

step "Employee signs in and creates their own AI key"
login "$employee" "$EMPLOYEE_EMAIL" "$EMPLOYEE_PASSWORD"
key="$(call "$employee" POST /platform/ai/keys "{\"name\":\"laptop\",\"expires_in_days\":7,\"api_scope\":[\"$API/v1\"]}" | json "d['key']")"
echo "key: ${key:0:10}… (shown once)"

step "Employee sends requests through the gateway"
for i in 1 2 3 4; do
  code="$(chat "$key")"
  if [ "$code" = 200 ]; then
    echo "request $i: HTTP 200 -> $(json "d['choices'][0]['message']['content'][:60] + '…'" < "$work/chat")"
  else
    echo "request $i: HTTP $code -> $(json "d.get('error_code', '') + ' ' + str(d.get('error_message', d))" < "$work/chat")"
  fi
done

step "Employee's usage and allowance"
sleep 1
call "$employee" GET /platform/ai/budgets/status | json "'\n'.join(f\"{b['name']}: {b['used']}/{b['limit_value']} {b['limit_type']} ({b['percent']}%), resets {b['resets_at']}\" for b in (d.get('budgets') or d.get('response',{}).get('budgets') or []))"

step "Bonus: the same gateway also routes regular APIs"
call "$admin" GET "/platform/api/all?page_size=100" | json "'\\n'.join(sorted(f\"{a['api_type']:5} /api/{'ai/' if a['api_type'] == 'AI' else 'rest/'}{a['api_name']}/{a['api_version']}\" for a in d['apis']))"

printf '\nOpen http://127.0.0.1:3000 as %s to see the same data in AI Gateway → Usage and Allowances.\n' "$ADMIN_EMAIL"
