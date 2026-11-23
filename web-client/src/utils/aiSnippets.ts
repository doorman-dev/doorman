import type { AiProvider } from '@/utils/ai'

export interface AiSnippet { id: string; label: string; language: string; code: string }

/**
 * Copy-paste setup for one AI API. `baseUrl` is the SDK base URL
 * (`aiSdkBaseUrl`), `model` a concrete allowed model, and `key` either the
 * employee's key or a placeholder. Mirrors user-docs/08-ai-gateway.md.
 */
export function aiSnippets(provider: AiProvider, baseUrl: string, model: string, key = 'dk_your_key_here', allowedModels: string[] = []): AiSnippet[] {
  const env = (vars: [string, string][]) => vars.map(([name, value]) => `export ${name}="${value}"`).join('\n')
  const quoted = JSON.stringify
  const matchingModel = (test: RegExp, fallback: string) => [model, ...allowedModels]
    .find(candidate => !candidate.endsWith('*') && test.test(candidate)) || fallback
  if (provider === 'bedrock') {
    const claudeModel = matchingModel(/(?:^|\/)(?:(?:us|eu|apac|global)\.)?anthropic\./, 'YOUR_ALLOWED_CLAUDE_MODEL')
    const messages = [{ role: 'user', content: 'Hello' }]
    const converse = [{ role: 'user', content: [{ text: 'Hello' }] }]
    return [
      { id: 'claude-code', label: 'Claude Code', language: 'bash', code: `${env([['CLAUDE_CODE_USE_BEDROCK', '1'], ['ANTHROPIC_BEDROCK_BASE_URL', baseUrl], ['AWS_REGION', 'us-east-1'], ['CLAUDE_CODE_SKIP_BEDROCK_AUTH', '1'], ['ANTHROPIC_CUSTOM_HEADERS', `Authorization: Bearer ${key}`], ['ANTHROPIC_MODEL', claudeModel]])}\nclaude` },
      { id: 'boto3', label: 'boto3', language: 'python', code: `import os\nimport boto3\n\nos.environ["AWS_BEARER_TOKEN_BEDROCK"] = os.environ["DOORMAN_AI_KEY"]\nclient = boto3.client("bedrock-runtime", region_name="us-east-1", endpoint_url=${quoted(baseUrl)})\nreply = client.converse(modelId=${quoted(model)}, messages=${quoted(converse)})\nprint(reply["output"]["message"]["content"][0]["text"])` },
      { id: 'aws-js', label: 'AWS SDK for JS', language: 'typescript', code: `import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime'\n\nconst client = new BedrockRuntimeClient({\n  region: 'us-east-1', endpoint: ${quoted(baseUrl)},\n  token: async () => ({ token: process.env.DOORMAN_AI_KEY! }),\n  authSchemePreference: ['httpBearerAuth'],\n})\nconst reply = await client.send(new ConverseCommand({\n  modelId: ${quoted(model)}, messages: ${quoted(converse)},\n}))` },
      { id: 'anthropic-python', label: 'Anthropic Python', language: 'python', code: `import os\nfrom anthropic import AnthropicBedrock\n\nclient = AnthropicBedrock(base_url=${quoted(baseUrl)}, aws_region="us-east-1",\n                          api_key=os.environ["DOORMAN_AI_KEY"])\nreply = client.messages.create(model=${quoted(claudeModel)}, max_tokens=256,\n                               messages=${quoted(messages)})` },
      { id: 'anthropic-ts', label: 'Anthropic TypeScript', language: 'typescript', code: `import { AnthropicBedrock } from '@anthropic-ai/bedrock-sdk'\n\nconst client = new AnthropicBedrock({\n  baseURL: ${quoted(baseUrl)}, awsRegion: 'us-east-1',\n  apiKey: process.env.DOORMAN_AI_KEY,\n})\nconst reply = await client.messages.create({\n  model: ${quoted(claudeModel)}, max_tokens: 256, messages: ${quoted(messages)},\n})` },
    ]
  }
  if (provider === 'vertex') {
    const claudeModel = matchingModel(/^claude-/, 'YOUR_ALLOWED_CLAUDE_MODEL')
    const geminiModel = matchingModel(/^gemini-/, 'YOUR_ALLOWED_GEMINI_MODEL')
    const project = 'your-project'
    const location = 'global'
    const claudeUrl = `${baseUrl}/v1`
    const messages = [{ role: 'user', content: 'Hello' }]
    return [
      { id: 'claude-code', label: 'Claude Code', language: 'bash', code: `${env([['CLAUDE_CODE_USE_VERTEX', '1'], ['ANTHROPIC_VERTEX_BASE_URL', claudeUrl], ['CLOUD_ML_REGION', location], ['ANTHROPIC_VERTEX_PROJECT_ID', project], ['CLAUDE_CODE_SKIP_VERTEX_AUTH', '1'], ['ANTHROPIC_CUSTOM_HEADERS', `Authorization: Bearer ${key}`], ['ANTHROPIC_MODEL', claudeModel]])}\nclaude` },
      { id: 'google-python', label: 'Google Gen AI Python', language: 'python', code: `import os\nfrom google import genai\nfrom google.genai import types\nfrom google.oauth2.credentials import Credentials\n\n# Vertex mode always loads Google credentials: pass the Doorman key as the token.\nclient = genai.Client(\n    vertexai=True, project=${quoted(project)}, location=${quoted(location)},\n    credentials=Credentials(token=os.environ["DOORMAN_AI_KEY"]),\n    http_options=types.HttpOptions(base_url=${quoted(baseUrl)}, api_version="v1"),\n)\nreply = client.models.generate_content(model=${quoted(geminiModel)}, contents="Hello")\nprint(reply.text)` },
      { id: 'anthropic-python', label: 'Anthropic Python', language: 'python', code: `import os\nfrom anthropic import AnthropicVertex\n\nclient = AnthropicVertex(base_url=${quoted(claudeUrl)}, project_id=${quoted(project)},\n                         region=${quoted(location)}, access_token=os.environ["DOORMAN_AI_KEY"])\nreply = client.messages.create(model=${quoted(claudeModel)}, max_tokens=256,\n                               messages=${quoted(messages)})` },
      { id: 'anthropic-ts', label: 'Anthropic TypeScript', language: 'typescript', code: `import { AnthropicVertex } from '@anthropic-ai/vertex-sdk'\nimport { OAuth2Client } from 'google-auth-library'\n\nconst authClient = new OAuth2Client()\nauthClient.setCredentials({ access_token: process.env.DOORMAN_AI_KEY })\nconst client = new AnthropicVertex({\n  baseURL: ${quoted(claudeUrl)}, projectId: ${quoted(project)},\n  region: ${quoted(location)}, authClient,\n})\nconst reply = await client.messages.create({\n  model: ${quoted(claudeModel)}, max_tokens: 256, messages: ${quoted(messages)},\n})` },
    ]
  }
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
