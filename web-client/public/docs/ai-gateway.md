# AI Gateway

Draft: endpoint and UI verification will be completed with the AI gateway rollout.

Doorman gives employees and internal applications one governed endpoint for your
organization's AI providers. Your organization supplies its own provider API keys
(BYOK). Doorman applies existing authentication, subscriptions, groups, roles,
network controls and API lifecycle policies, then records usage and enforces AI
model access, budgets and guardrails.

## Roll out AI to your employees

The fastest path is **AI Setup** in the sidebar (requires `manage_ai`,
`manage_apis` and `manage_credits`). It takes four steps:

1. **Providers.** Tick OpenAI, Anthropic, Gemini, Azure OpenAI or an
   OpenAI-compatible server, paste each company API key once, and list the
   allowed models (`gpt-*`, `claude-*`, …). Keys are encrypted and never shown
   to employees.
2. **Who gets access.** Everyone, or selected groups. No per-person
   subscriptions are needed: anyone in those groups, including people who join
   later, can use the providers.
3. **Allowances.** Pick how usage is limited, per provider and per month:

   | Plan | Example | Budget created |
   |------|---------|----------------|
   | Same allowance for every employee | $50 OpenAI + $30 Claude each | scope `global`, `per_user: true`, one per provider |
   | One shared company pool | $2,000 OpenAI for the whole company | scope `global`, `per_user: false` |
   | Different allowance per group | Engineering $100 each, Sales $20 each | scope `group`, `per_user: true` |
   | Different allowance per tier | Pro $100 each, Standard $10 each | scope `tier`, `per_user: true` |
   | No limits | track usage only | none |

   Choose dollars or tokens, and whether hitting the limit **blocks** until the
   next period or only **warns**. Dollar allowances need prices: the wizard asks
   for your contract rates for any provider that has none yet.
4. **Review** and **Create everything**. The final screen has a message to send
   to employees.

**Individual exceptions** (one person gets more) are a *One user* budget in
**Credits → AI Budgets**. When several budgets apply, every one is enforced, so
a person can have both a personal Claude allowance and a share of a company pool.

### What employees do

Employees open **My AI** in the sidebar. It shows their allowance per provider
(used, left, reset date), lets them create a personal `dk_` access key (shown
once), and gives copy-paste setup for every provider they can use: environment
variables for most tools, Claude Code, Python, Node.js and curl, already filled
in with the right base URL and an allowed model. When an allowance runs out,
requests return `AI004` with the reset time; `downgrade` budgets switch to a
cheaper model instead.

## Set up a provider

1. In **Credits → Credit definitions**, create a provider credential using the
   matching preset. Store your organization's provider-console API key. Provider
   credentials can have an empty credit-tier list. Consumer subscriptions such
   as ChatGPT Plus, Claude Pro/Max and Gemini subscriptions are unsupported.
2. In **APIs → Add API**, select **AI (LLM provider)** and the provider. Choose a
   name/version, upstream server and credential group. Public access is disabled;
   authentication is required. Per-group credential overrides select your
   organization's separate provider accounts when needed.
3. Add a nonempty allowed-model list. Exact IDs and trailing `*` prefixes work.
   Aliases map friendly names to allowed models. Set an optional output-token cap
   and allow streaming as needed. Keep user attribution enabled where supported.
   Local model lists show concrete allowed IDs; trailing-`*` rules are not expanded
   into a provider model catalog.
4. Grant users/groups access through the API's normal policy and subscriptions,
   then activate its version. To grant access by group membership alone (no
   per-person subscriptions), set `api_ai_config.require_subscription` to
   `false`; members of `api_allowed_groups` (`ALL` = everyone) can then call it.
   AI Setup does this for you.
5. In **Settings → My AI access keys**, create a scoped key, copy it once and
   store it securely. Use that Doorman key in your SDK. Provider keys stay in the
   gateway vault. Revoke lost keys from the same panel.

Rotating `TOKEN_ENCRYPTION_KEY` or `MEM_ENCRYPTION_KEY` invalidates all issued
`dk_` access keys because their hashes use deployment-derived key material.
Plan to issue replacement access keys when rotating that material.

| Provider | Upstream server | SDK base URL for an example API |
| --- | --- | --- |
| OpenAI | `https://api.openai.com` | `https://gw.example.com/api/ai/corp-openai/v1/v1` |
| Anthropic | `https://api.anthropic.com` | `https://gw.example.com/api/ai/corp-claude/v1` |
| Gemini API | `https://generativelanguage.googleapis.com` | `https://gw.example.com/api/ai/corp-gemini/v1` |
| Azure OpenAI | Your resource's `https://RESOURCE.openai.azure.com` | `https://gw.example.com/api/ai/corp-azure/v1` |
| OpenAI-compatible | Your configured server, such as `http://ollama:11434` | `https://gw.example.com/api/ai/local-llm/v1/v1` |

Copy the base URL from the API's **Connect your SDK** box. In the OpenAI example,
the first `v1` is the Doorman API version and the second is OpenAI's path prefix.
For Azure, allowed models are deployment names; the SDK must supply the provider
`api-version` query parameter. Compatible providers can use a custom API-key
header from the credit definition. The explicit credential group `none` is only
permitted for compatible upstreams on private networks or Docker service names.

## Connect an SDK

Set `DOORMAN_AI_KEY` in your application's environment to its Doorman access key.
These snippets make no assumptions about provider keys or model entitlements.

### OpenAI

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="https://gw.example.com/api/ai/corp-openai/v1/v1",
    api_key=os.environ["DOORMAN_AI_KEY"],
)
reply = client.chat.completions.create(
    model="YOUR_ALLOWED_MODEL",
    messages=[{"role": "user", "content": "Hello"}],
)
```

```typescript
import OpenAI from 'openai'

const client = new OpenAI({
  baseURL: 'https://gw.example.com/api/ai/corp-openai/v1/v1',
  apiKey: process.env.DOORMAN_AI_KEY,
})
const reply = await client.chat.completions.create({
  model: 'YOUR_ALLOWED_MODEL',
  messages: [{ role: 'user', content: 'Hello' }],
})
```

### Anthropic

```python
import os
import anthropic

client = anthropic.Anthropic(
    base_url="https://gw.example.com/api/ai/corp-claude/v1",
    api_key=os.environ["DOORMAN_AI_KEY"],
)
reply = client.messages.create(
    model="claude-opus-5-5", max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

```typescript
import Anthropic from '@anthropic-ai/sdk'

const client = new Anthropic({
  baseURL: 'https://gw.example.com/api/ai/corp-claude/v1',
  apiKey: process.env.DOORMAN_AI_KEY,
})
const reply = await client.messages.create({
  model: 'claude-opus-5-5', max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hello' }],
})
```

### Gemini

```python
import os
from google import genai
from google.genai import types

client = genai.Client(
    api_key=os.environ["DOORMAN_AI_KEY"],
    http_options=types.HttpOptions(
        base_url="https://gw.example.com/api/ai/corp-gemini/v1",
    ),
)
reply = client.models.generate_content(
    model="YOUR_ALLOWED_MODEL", contents="Hello",
)
```

```typescript
import { GoogleGenAI } from '@google/genai'

const client = new GoogleGenAI({
  apiKey: process.env.DOORMAN_AI_KEY,
  httpOptions: { baseUrl: 'https://gw.example.com/api/ai/corp-gemini/v1' },
})
const reply = await client.models.generateContent({
  model: 'YOUR_ALLOWED_MODEL', contents: 'Hello',
})
```

## Usage, pricing and budgets

**Analytics → AI Usage** shows requests, uncached input, output, cache reads and
writes, spend and active users. Thinking tokens from Gemini count as output.
OpenAI reasoning tokens are already part of output and are never charged twice.
Missing provider usage is estimated from bytes; analytics marks estimated and
unpriced requests.

The **Breakdown** section splits spend by **Employees, Groups, Roles, Tiers,
Providers, Models or AI APIs**, and the filters (provider, model, group, role,
tier and date range) apply to every chart and table. Select a group, role, tier,
provider or model to see the employees behind it; select an employee for their
usage by provider and model. Each request counts under the employee's groups,
role and tier at the time it was made. Usage recorded before role and tier
snapshots existed uses the employee's current role and tier. The same filters
are available on the API as `provider`, `model`, `group`, `role`, `tier` and
`username`, and `dimension` accepts `user`, `group`, `role`, `tier`, `provider`,
`model` or `api`. Models without a matching price cost zero until an admin
configures pricing; that zero does not mean provider access is free.

In **Credits → AI Pricing**, configure your own USD-per-million-token rates and
effective dates. Exact model rules take priority, followed by the longest `*`
prefix. An empty cache-write rate uses the input rate. Example prices are starting
points that must be checked against your provider contract. Costs are stored as
integer nano-USD (`$1 = 1,000,000,000` nanos) and displayed to six decimal places.

**Reports → AI chargeback** exports metadata CSV by user or group, with `role`,
`tier` and `provider` columns for pivoting. Users in
multiple groups contribute to each group, so adding group totals may double-count.
There is no bulk export of prompt/completion pairs.

**Credits → AI Budgets** supports daily, weekly (ISO week) and monthly budgets
for one user, a group, a tier, one AI API or everyone. A budget can be limited
to one **provider** (only requests to that provider count). For group, tier, API
and everyone budgets, choose **one shared pool** or **each member gets this
amount** (`per_user`); a per-member budget's list row shows the total across
members, and each person sees their own usage on My AI. Actions warn, downgrade to an
allowed model, or block. Periods use UTC. Token budgets count uncached input,
output and cache writes; cache reads are excluded. A tier's monthly token
allowance acts as a per-user blocking budget.

Budgets are **soft limits**: requests already in flight can each exceed the limit
by one request. They do not reserve cost before a generation starts. Cost limits
are entered in dollars in the UI and stored as integer nanos in the API.

Review your own usage in **My AI**, **Quota → AI usage** or **Settings → My AI access keys**.
Administrators manage budgets in **Credits → AI Budgets**; Groups and Users have
shortcuts that prefill the budget target. Usage bars show each budget's current
period, independently of the analytics date range.

## Guardrails and prompt privacy

In **Security → AI Guardrails**, configure built-in email, US SSN, credit-card,
AWS access-key, private-key and generic API-key detectors, or your own regexes
and keywords. Scope rails to APIs/groups and choose input, output or both.
Actions redact (`[REDACTED:detector]`), block or log detector counts. Dry-run mode
records matches without altering content. Test with sample text before enforcing.
Image, tool-use and tool-result blocks are left untouched.

Output guardrails on streaming responses are **log-only** in this release;
they cannot prevent content reaching the client. Nonstreaming output guardrails
can redact or block. Provider safety refusals pass through without attempts to
evade them. Match outcomes contain detector names and counts, never matched text;
the explicit admin sample-text test returns spans for the supplied text.

The default prompt log level is **Metadata**. A per-API override can only reduce
the global level; it cannot enable Full while the global setting is Metadata or
None. **Full** stores encrypted prompt
and completion text, capped at 256 KiB each, after configured redaction. An admin
must configure employee notice text in **Settings → AI gateway**, and every
user then sees the notice as a dismissible banner. Full logging needs
`TOKEN_ENCRYPTION_KEY` (or `MEM_ENCRYPTION_KEY`); without one, prompts are not
stored and the gateway logs an error. Retention (1–3650 days, default 30) is
enforced by the background purge task, which runs every
`REVOCATION_PURGE_INTERVAL_SECONDS` (default 300 s), not by a database TTL index,
so expired prompts can remain for up to one interval. Users with `view_logs` can view individual retained prompts;
deletion requires `manage_security`. **None** disables content-related activity
details; usage counts remain available for budgets and analytics. Streams emit
a separate `type: "ai_usage"` activity record linked by request ID.

## Compliance responsibilities

- **C1 — Your provider account:** every provider credential belongs to your
  organization. Doorman supplies no shared or fallback provider key.
- **C2 — API access only:** consumer subscription/session tokens are unsupported;
  inbound cookies and provider-key headers are stripped before forwarding.
- **C3 — Respect provider limits:** key rotation replaces credentials without
  pooling accounts. A provider 429 and its `Retry-After` pass through; Doorman
  never switches keys to evade that limit.
- **C4 — Per-user attribution:** supported providers receive a stable pseudonymous
  user ID when enabled. OpenAI uses `safety_identifier`, Anthropic uses
  `metadata.user_id`, and Azure uses `user`. Existing client values are preserved.
  Gemini has no corresponding attribution field.
- **C5 — Provider safety:** refusals remain visible, and guardrails only redact,
  block or report detector counts.
- **C6 — Minimize content reuse:** metadata chargeback exports are available;
  bulk training-dataset exports are not.
- **C7 — Tenant isolation:** hosted tenants use separate storage and credentials;
  a tenant's access key cannot authorize another tenant's gateway.
- **C8 — Employee notice:** start with metadata logging, give employees the
  required notice before enabling full content logging, choose appropriate
  retention and restrict access. Review your applicable workplace/privacy rules.

Administrators remain responsible for provider terms, organizational policies
and legal obligations. Check current terms before production rollout.

## Errors and limits

Gateway errors use `{error_code, error_message}`. Provider errors retain their
native status/body so official SDK exception handling still works.

| Code | HTTP | Meaning |
| --- | --- | --- |
| AI001 | 404 | Operation is not allowed |
| AI002 | 403 | Requested model is not allowed |
| AI003 | 400 | Invalid JSON or missing model |
| AI004 | 429 | Budget exceeded; includes budget name and reset time |
| AI005 | 400 | Guardrail blocked content; never includes matched text |
| AI006 | 502 | Provider credential is missing or cannot be decrypted |
| AI007 | 401 | Access key is invalid, expired or revoked |
| AI008 | 400 | Streaming is disabled for this API |
| AI009 | 400 | Invalid AI API configuration |
| AI010 | 504 | Provider first-byte timeout |

Inspect `X-Doorman-AI-Model`, `X-Doorman-AI-Model-Downgraded`,
`X-Doorman-AI-Budget-Warning` and `X-Doorman-AI-Redactions` when diagnosing policy.
Provider rate-limit and request-ID headers are preserved.

Supported operations are OpenAI chat, Responses and embeddings; Anthropic
messages and token counting; Gemini generation, token counting and embeddings;
and Azure deployment chat/embeddings. Model lists are governed local lists.
Files, batches, fine-tuning, realtime/WebSockets, assistants, image generation,
native Vertex AI and Bedrock are outside this release.

Gemini `streamGenerateContent` without `alt=sse` returns its JSON array buffered
until completion. SSE responses pass bytes through incrementally. AI uses a
60-second default first-byte timeout and 120-second stream-idle timeout, both
configurable per API. AI request bodies default to 32 MiB. Access keys are limited
to 20 active keys per user, with optional expiration of 1–365 days.

See the Configuration Reference for `MAX_BODY_SIZE_AI`, `AI_USER_ID_SALT`,
`DOORMAN_EGRESS_IPS` and `DOORMAN_AI_LIVE_TEST`. Changing the attribution salt
changes the pseudonymous IDs providers see. Egress IPs are displayed for provider
allowlisting; the setting does not configure networking.
