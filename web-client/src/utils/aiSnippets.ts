import type { AiProvider } from '@/utils/ai'

export interface AiSnippet { id: string; label: string; language: string; code: string }

/**
 * Copy-paste setup for one AI API. `baseUrl` is the SDK base URL
 * (`aiSdkBaseUrl`), `model` a concrete allowed model, and `key` either the
 * employee's key or a placeholder. Mirrors user-docs/08-ai-gateway.md.
 */
export function aiSnippets(provider: AiProvider, baseUrl: string, model: string, key = 'dk_your_key_here'): AiSnippet[] {
  const env = (vars: [string, string][]) => vars.map(([name, value]) => `export ${name}="${value}"`).join('\n')
  if (provider === 'anthropic') {
    return [
      { id: 'claude-code', label: 'Claude Code', language: 'bash', code: `${env([['ANTHROPIC_BASE_URL', baseUrl], ['ANTHROPIC_API_KEY', key]])}\nclaude` },
      { id: 'python', label: 'Python', language: 'python', code: `import os\nimport anthropic\n\nclient = anthropic.Anthropic(\n    base_url="${baseUrl}",\n    api_key=os.environ["DOORMAN_AI_KEY"],\n)\nreply = client.messages.create(\n    model="${model}", max_tokens=1024,\n    messages=[{"role": "user", "content": "Hello"}],\n)\nprint(reply.content[0].text)` },
      { id: 'node', label: 'Node.js', language: 'typescript', code: `import Anthropic from '@anthropic-ai/sdk'\n\nconst client = new Anthropic({\n  baseURL: '${baseUrl}',\n  apiKey: process.env.DOORMAN_AI_KEY,\n})\nconst reply = await client.messages.create({\n  model: '${model}', max_tokens: 1024,\n  messages: [{ role: 'user', content: 'Hello' }],\n})` },
      { id: 'curl', label: 'curl', language: 'bash', code: `curl ${baseUrl}/v1/messages \\\n  -H "x-api-key: $DOORMAN_AI_KEY" \\\n  -H "anthropic-version: 2023-06-01" \\\n  -H "content-type: application/json" \\\n  -d '{"model":"${model}","max_tokens":256,"messages":[{"role":"user","content":"Hello"}]}'` },
    ]
  }
  if (provider === 'gemini') {
    return [
      { id: 'python', label: 'Python', language: 'python', code: `import os\nfrom google import genai\nfrom google.genai import types\n\nclient = genai.Client(\n    api_key=os.environ["DOORMAN_AI_KEY"],\n    http_options=types.HttpOptions(base_url="${baseUrl}"),\n)\nreply = client.models.generate_content(model="${model}", contents="Hello")\nprint(reply.text)` },
      { id: 'node', label: 'Node.js', language: 'typescript', code: `import { GoogleGenAI } from '@google/genai'\n\nconst client = new GoogleGenAI({\n  apiKey: process.env.DOORMAN_AI_KEY,\n  httpOptions: { baseUrl: '${baseUrl}' },\n})\nconst reply = await client.models.generateContent({ model: '${model}', contents: 'Hello' })` },
      { id: 'curl', label: 'curl', language: 'bash', code: `curl "${baseUrl}/v1beta/models/${model}:generateContent" \\\n  -H "x-goog-api-key: $DOORMAN_AI_KEY" \\\n  -H "content-type: application/json" \\\n  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'` },
    ]
  }
  // OpenAI, Azure OpenAI and OpenAI-compatible all speak the OpenAI SDK.
  return [
    { id: 'env', label: 'Env vars (most tools)', language: 'bash', code: env([['OPENAI_BASE_URL', baseUrl], ['OPENAI_API_KEY', key]]) },
    { id: 'python', label: 'Python', language: 'python', code: `import os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    base_url="${baseUrl}",\n    api_key=os.environ["DOORMAN_AI_KEY"],\n)\nreply = client.chat.completions.create(\n    model="${model}",\n    messages=[{"role": "user", "content": "Hello"}],\n)\nprint(reply.choices[0].message.content)` },
    { id: 'node', label: 'Node.js', language: 'typescript', code: `import OpenAI from 'openai'\n\nconst client = new OpenAI({\n  baseURL: '${baseUrl}',\n  apiKey: process.env.DOORMAN_AI_KEY,\n})\nconst reply = await client.chat.completions.create({\n  model: '${model}',\n  messages: [{ role: 'user', content: 'Hello' }],\n})` },
    { id: 'curl', label: 'curl', language: 'bash', code: `curl ${baseUrl}/chat/completions \\\n  -H "authorization: Bearer $DOORMAN_AI_KEY" \\\n  -H "content-type: application/json" \\\n  -d '{"model":"${model}","messages":[{"role":"user","content":"Hello"}]}'` },
  ]
}
