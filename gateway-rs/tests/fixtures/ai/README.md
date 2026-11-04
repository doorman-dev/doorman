# AI provider fixtures

These fixtures are hand-made from the provider API references, checked on
**2026-10-18**. They are synthetic responses, not recorded provider traffic.
Identifiers, text, model placeholders, token counts and vectors are test data;
no provider credentials are included. Anthropic model IDs follow the project plan.

- [OpenAI chat and streaming](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events)
- [OpenAI Responses events](https://developers.openai.com/api/reference/resources/responses/streaming-events)
- [OpenAI embeddings](https://developers.openai.com/api/reference/resources/embeddings/methods/create)
- [Anthropic messages](https://platform.claude.com/docs/en/api/messages/create)
- [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming)
- [Anthropic token counting](https://platform.claude.com/docs/en/api/messages/count_tokens)
- [Gemini generation, safety and usage](https://ai.google.dev/api/generate-content)
- [Azure OpenAI chat](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/chat)

OpenAI chat's last chunk contains usage and an empty `choices` array; the
no-usage transcript exercises interrupted/missing metering. Responses usage is
inside `response.completed`. Anthropic output counts are cumulative, and cache
reads/writes are separate from uncached input. Gemini chunks and their JSON-array
equivalent carry successive usage snapshots; the last snapshot wins. Gemini
output billing includes candidate and thinking tokens. Refusals are HTTP 200
responses; `error_429.json` is an upstream HTTP 429 body.
