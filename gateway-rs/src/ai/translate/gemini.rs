//! OpenAI chat ⇄ Gemini GenerateContent, including Vertex Gemini.

use std::collections::HashMap;

use serde_json::{Value, json};

use super::{
    ChunkTranslator, NativeRequest, TranslateError,
    openai::{self, ChunkMeta, ResponseFormat, ToolChoice},
};
use crate::ai::{adapter::AiProvider, sse::SseEvent};

pub(super) fn to_native(
    provider: AiProvider,
    model: &str,
    chat: &Value,
) -> Result<NativeRequest, TranslateError> {
    let vertex = provider == AiProvider::Vertex;
    let stream = chat["stream"].as_bool().unwrap_or_default();
    let method = if stream {
        "streamGenerateContent"
    } else {
        "generateContent"
    };
    let prefix = if vertex {
        "v1/projects/-/locations/-/publishers/google/models"
    } else {
        "v1beta/models"
    };
    let rest_path = format!("{prefix}/{}:{method}", openai::path_segment(model));
    let query = if stream {
        vec![("alt".into(), "sse".into())]
    } else {
        Vec::new()
    };

    let mut system = Vec::new();
    let mut contents = Vec::new();
    let mut tool_names = HashMap::new();
    for message in openai::array_field(chat, "messages")? {
        let content = &message["content"];
        match message["role"].as_str().unwrap_or_default() {
            "system" | "developer" => system.extend(text_parts(content)?),
            "assistant" => {
                let mut parts = content_parts(content, vertex)?;
                for (index, call) in openai::array_field(message, "tool_calls")?
                    .iter()
                    .enumerate()
                {
                    let (id, name, arguments) = openai::tool_use(call)?;
                    tool_names.insert(id, name);
                    let mut part = json!({"functionCall": {"name": name, "args": arguments}});
                    if let Some(signature) = call["thought_signature"].as_str() {
                        part["thoughtSignature"] = json!(signature);
                    } else if index == 0
                        && gemini_version(model).is_some_and(|(major, _)| major >= 3)
                    {
                        // Google documents this marker for tool calls imported from another API.
                        // https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/thinking/thought-signatures
                        part["thoughtSignature"] = json!("skip_thought_signature_validator");
                    }
                    parts.push(part);
                }
                push_content(&mut contents, "model", parts)?;
            }
            "tool" => {
                let id = openai::tool_result_id(message)?;
                let name = tool_names.get(id).ok_or_else(|| {
                    TranslateError(
                        "Gemini tool results require a matching assistant tool call".into(),
                    )
                })?;
                let text = text_parts(content)?
                    .iter()
                    .filter_map(|part| part["text"].as_str())
                    .collect::<String>();
                let response = match serde_json::from_str::<Value>(&text) {
                    Ok(value) if value.is_object() => value,
                    Ok(value) => json!({"result": value}),
                    Err(_) => json!({"result": text}),
                };
                push_content(
                    &mut contents,
                    "user",
                    vec![json!({
                        "functionResponse": {"name": name, "response": response},
                    })],
                )?;
            }
            _ => push_content(&mut contents, "user", content_parts(content, vertex)?)?,
        }
    }
    if contents.is_empty() {
        return Err(TranslateError(
            "Gemini requires at least one conversation message".into(),
        ));
    }
    let mut body = json!({"contents": contents});
    if !system.is_empty() {
        body["systemInstruction"] = json!({"parts": system});
    }
    let config = generation_config(model, chat)?;
    if config != json!({}) {
        body["generationConfig"] = config;
    }
    configure_tools(chat, &mut body)?;

    Ok(NativeRequest {
        rest_path,
        query,
        body,
        stream,
    })
}

fn push_content(
    contents: &mut Vec<Value>,
    role: &str,
    parts: Vec<Value>,
) -> Result<(), TranslateError> {
    if parts.is_empty() {
        return Err(TranslateError(
            "Gemini conversation messages require content or tool calls".into(),
        ));
    }
    if let Some(previous) = contents
        .last_mut()
        .filter(|content| content["role"] == role)
        && let Some(previous_parts) = previous["parts"].as_array_mut()
    {
        previous_parts.extend(parts);
    } else {
        contents.push(json!({"role": role, "parts": parts}));
    }
    Ok(())
}

fn text_parts(content: &Value) -> Result<Vec<Value>, TranslateError> {
    let parts = content_parts(content, false)?;
    if parts.iter().any(|part| part.get("text").is_none()) {
        return Err(TranslateError(
            "Gemini system and tool messages require text".into(),
        ));
    }
    Ok(parts)
}

fn content_parts(content: &Value, vertex: bool) -> Result<Vec<Value>, TranslateError> {
    match content {
        Value::Null => Ok(Vec::new()),
        Value::String(text) if text.is_empty() => Ok(Vec::new()),
        Value::String(text) => Ok(vec![json!({"text": text})]),
        Value::Array(parts) => parts
            .iter()
            .map(|part| match part["type"].as_str() {
                Some("text") => part["text"]
                    .as_str()
                    .map(|text| json!({"text": text}))
                    .ok_or_else(|| TranslateError("text content parts require text".into())),
                Some("image_url") => image_part(openai::image_url(part)?, vertex),
                _ => Err(TranslateError(
                    "Gemini supports text and image_url content parts".into(),
                )),
            })
            .collect(),
        _ => Err(TranslateError(
            "message content must be text or an array of content parts".into(),
        )),
    }
}

fn image_part(url: &str, vertex: bool) -> Result<Value, TranslateError> {
    if url.starts_with("data:") {
        let (mime_type, data) = openai::base64_image(url)?;
        return Ok(json!({"inlineData": {"mimeType": mime_type, "data": data}}));
    }
    let parsed = openai::https_image(url)?;
    if !vertex {
        return Err(TranslateError(
            "Gemini Developer API requires inline base64 image data URLs".into(),
        ));
    }
    let extension = parsed
        .path()
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase());
    let mime = match extension.as_deref() {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        Some("heic") => "image/heic",
        Some("heif") => "image/heif",
        _ => return Err(TranslateError(
            "Vertex HTTPS image URLs require a recognized image extension; use inline base64 otherwise".into(),
        )),
    };
    Ok(json!({"fileData": {"mimeType": mime, "fileUri": url}}))
}

fn configure_tools(chat: &Value, body: &mut Value) -> Result<(), TranslateError> {
    let choice = openai::tool_choice(chat)?;
    let mut declarations = Vec::new();
    for tool in openai::array_field(chat, "tools")? {
        let (name, function) = openai::tool_definition(tool)?;
        let mut declaration = json!({
            "name": name, "parameters": schema(&openai::tool_parameters(function)),
        });
        if let Some(description) = function["description"].as_str() {
            declaration["description"] = json!(description);
        }
        declarations.push(declaration);
    }
    if declarations.is_empty() {
        return if matches!(choice, ToolChoice::Required | ToolChoice::Named(_)) {
            Err(TranslateError(
                "tool_choice requires at least one function tool".into(),
            ))
        } else {
            Ok(())
        };
    }
    body["tools"] = json!([{"functionDeclarations": declarations}]);
    let config = match choice {
        ToolChoice::Default => return Ok(()),
        ToolChoice::Auto => json!({"mode": "AUTO"}),
        ToolChoice::None => json!({"mode": "NONE"}),
        ToolChoice::Required => json!({"mode": "ANY"}),
        ToolChoice::Named(name) => json!({"mode": "ANY", "allowedFunctionNames": [name]}),
    };
    body["toolConfig"] = json!({"functionCallingConfig": config});
    Ok(())
}

fn generation_config(model: &str, chat: &Value) -> Result<Value, TranslateError> {
    let mut config = json!({});
    if let Some(limit) = openai::output_token_limit(chat)? {
        config["maxOutputTokens"] = json!(limit);
    }
    if let Some(stop) = openai::stop_sequences(chat)? {
        config["stopSequences"] = stop;
    }
    for (source, target) in [("temperature", "temperature"), ("top_p", "topP")] {
        if let Some(value) = chat.get(source).filter(|value| !value.is_null()) {
            config[target] = value.clone();
        }
    }
    match openai::response_format(chat)? {
        ResponseFormat::Text => {}
        ResponseFormat::JsonObject => config["responseMimeType"] = json!("application/json"),
        ResponseFormat::JsonSchema {
            schema: definition, ..
        } => {
            config["responseMimeType"] = json!("application/json");
            config["responseSchema"] = schema(definition);
        }
    }
    if let Some(effort) = openai::reasoning_effort(chat)? {
        config["thinkingConfig"] = thinking_config(model, effort)?;
    }
    Ok(config)
}

fn schema(raw: &Value) -> Value {
    let Some(fields) = raw.as_object() else {
        return raw.clone();
    };
    // Gemini's OpenAPI Schema excludes JSON Schema fields such as $schema, $id,
    // $defs, $ref, additionalProperties, patternProperties, oneOf and allOf.
    // https://aistudio.google.com/api-reference/generate-content/generate-content#Resource:Schema
    let mut native = json!({});
    for (key, value) in fields {
        match key.as_str() {
            "type" => {
                if let Some(kind) = value.as_str() {
                    native["type"] = json!(kind.to_ascii_uppercase());
                } else if let Some(types) = value.as_array() {
                    let alternatives = types
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|kind| *kind != "null")
                        .collect::<Vec<_>>();
                    if types.iter().any(|kind| kind == "null") {
                        native["nullable"] = json!(true);
                    }
                    match alternatives.as_slice() {
                        [kind] => native["type"] = json!(kind.to_ascii_uppercase()),
                        [] => native["type"] = json!("NULL"),
                        _ => {
                            native["anyOf"] = json!(
                                alternatives
                                    .iter()
                                    .map(|kind| json!({"type": kind.to_ascii_uppercase()}))
                                    .collect::<Vec<_>>()
                            )
                        }
                    }
                }
            }
            "properties" => {
                if let Some(properties) = value.as_object() {
                    native[key] = Value::Object(
                        properties
                            .iter()
                            .map(|(name, value)| (name.clone(), schema(value)))
                            .collect(),
                    );
                }
            }
            "items" => native[key] = schema(value),
            "anyOf" => {
                if let Some(options) = value.as_array() {
                    native[key] = Value::Array(options.iter().map(schema).collect());
                }
            }
            "description" | "format" | "enum" | "nullable" | "required" | "propertyOrdering"
            | "minimum" | "maximum" | "minItems" | "maxItems" | "minLength" | "maxLength"
            | "minProperties" | "maxProperties" | "pattern" => native[key] = value.clone(),
            _ => {}
        }
    }
    native
}

fn gemini_version(model: &str) -> Option<(u32, u32)> {
    let version = model.strip_prefix("gemini-")?;
    let mut parts = version.split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()
        .and_then(|part| part.parse().ok())
        .unwrap_or_default();
    Some((major, minor))
}

fn thinking_config(model: &str, effort: &str) -> Result<Value, TranslateError> {
    match gemini_version(model) {
        Some((3.., _)) => {
            let flash = model.contains("flash");
            let level = match effort {
                "none" => {
                    return Err(TranslateError(
                        "This Gemini model cannot disable thinking".into(),
                    ));
                }
                "minimal" if flash => "MINIMAL",
                "minimal" | "low" => "LOW",
                "medium" if flash || !model.starts_with("gemini-3-pro") => "MEDIUM",
                _ => "HIGH",
            };
            Ok(json!({"thinkingLevel": level}))
        }
        Some((2, 5)) => {
            let budget = match effort {
                "none" if model.contains("flash") => 0,
                "none" => {
                    return Err(TranslateError(
                        "This Gemini model cannot disable thinking".into(),
                    ));
                }
                "minimal" if model.contains("flash-lite") => 512,
                "minimal" => 128,
                "low" => 1024,
                "medium" => 4096,
                _ => 8192,
            };
            Ok(json!({"thinkingBudget": budget}))
        }
        _ => Err(TranslateError(
            "This Gemini model has no supported reasoning_effort mapping".into(),
        )),
    }
}

fn usage(data: &Value) -> Value {
    let tokens = |key: &str| data[key].as_u64().unwrap_or_default();
    openai::usage(
        tokens("promptTokenCount"),
        tokens("candidatesTokenCount").saturating_add(tokens("thoughtsTokenCount")),
        tokens("cachedContentTokenCount"),
    )
}

fn parts(native: &Value) -> impl Iterator<Item = &Value> {
    native["candidates"][0]["content"]["parts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|part| part["thought"] != true)
}

fn function_call(part: &Value, index: usize) -> Option<Value> {
    let function = &part["functionCall"];
    let name = function["name"].as_str()?;
    let mut call = openai::tool_call(&format!("call_{index}"), name, &function["args"]);
    if let Some(signature) = part["thoughtSignature"].as_str() {
        call["thought_signature"] = json!(signature);
    }
    Some(call)
}

fn finish_reason(native: &Value) -> Option<&str> {
    native["candidates"][0]["finishReason"]
        .as_str()
        .or_else(|| {
            native["promptFeedback"]["blockReason"]
                .as_str()
                .map(|_| "SAFETY")
        })
}

pub(super) fn from_native(requested_model: &str, native: &Value) -> Value {
    let mut text = String::new();
    let mut calls = Vec::new();
    for part in parts(native) {
        if let Some(value) = part["text"].as_str() {
            text.push_str(value);
        } else if let Some(call) = function_call(part, calls.len()) {
            calls.push(call);
        }
    }
    let reason = if calls.is_empty() {
        openai::finish_reason(finish_reason(native))
    } else {
        "tool_calls"
    };
    openai::completion(
        requested_model,
        native["responseId"].as_str(),
        text,
        calls,
        reason,
        usage(&native["usageMetadata"]),
    )
}

pub(super) struct Chunks {
    meta: ChunkMeta,
    started: bool,
    closed: bool,
    tool_count: usize,
    reason: Option<&'static str>,
    usage: Value,
}

impl Chunks {
    pub(super) fn new(meta: ChunkMeta) -> Self {
        Self {
            meta,
            started: false,
            closed: false,
            tool_count: 0,
            reason: None,
            usage: usage(&Value::Null),
        }
    }
}

impl ChunkTranslator for Chunks {
    fn on_event(&mut self, event: &SseEvent) -> Vec<Value> {
        if self.closed {
            return Vec::new();
        }
        let Ok(data) = serde_json::from_str::<Value>(&event.data) else {
            return Vec::new();
        };
        if data["usageMetadata"].is_object() {
            self.usage = usage(&data["usageMetadata"]);
        }
        if let Some(reason) = finish_reason(&data) {
            self.reason = Some(openai::finish_reason(Some(reason)));
        }
        let mut chunks = Vec::new();
        if !self.started && data["candidates"][0].is_object() {
            self.started = true;
            chunks.push(self.meta.chunk(json!({"role": "assistant"}), None));
        }
        for part in parts(&data) {
            let delta = if let Some(text) = part["text"].as_str() {
                json!({"content": text})
            } else if let Some(mut call) = function_call(part, self.tool_count) {
                call["index"] = json!(self.tool_count);
                self.tool_count += 1;
                json!({"tool_calls": [call]})
            } else {
                continue;
            };
            chunks.push(self.meta.chunk(delta, None));
        }
        chunks
    }

    fn finish(&mut self) -> Vec<Value> {
        if self.closed {
            return Vec::new();
        }
        self.closed = true;
        let mut chunks = Vec::new();
        if !self.started {
            chunks.push(self.meta.chunk(json!({"role": "assistant"}), None));
        }
        let reason = if self.tool_count > 0 {
            "tool_calls"
        } else {
            self.reason.unwrap_or("stop")
        };
        chunks.push(self.meta.chunk(json!({}), Some(reason)));
        if self.meta.include_usage {
            chunks.push(self.meta.usage_chunk(std::mem::take(&mut self.usage)));
        }
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::translate::{self, Target};

    #[test]
    fn translates_config_tool_history_and_images() {
        let mut chat: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/translate/gemini/request.json"
        ))
        .unwrap();
        let request = translate::to_native(AiProvider::Gemini, "gemini-2.5-pro", &chat).unwrap();
        assert_eq!(
            request.rest_path,
            "v1beta/models/gemini-2.5-pro:streamGenerateContent"
        );
        assert_eq!(request.query, vec![("alt".into(), "sse".into())]);
        assert!(request.stream);
        assert_eq!(
            request.body["systemInstruction"]["parts"],
            json!([
                {"text":"Be concise."}, {"text":"Use Celsius."}
            ])
        );
        let contents = &request.body["contents"];
        assert_eq!(
            contents[0]["parts"][1],
            json!({"inlineData":{"mimeType":"image/png","data":"AA=="}})
        );
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(
            contents[1]["parts"][0],
            json!({
                "functionCall":{"name":"weather","args":{"city":"Paris"}},
                "thoughtSignature":"YWJj"
            })
        );
        assert_eq!(
            contents[2]["parts"][0],
            json!({
                "functionResponse":{"name":"weather","response":{"temperature":18}}
            })
        );
        let parameters = &request.body["tools"][0]["functionDeclarations"][0]["parameters"];
        assert_eq!(parameters["type"], "OBJECT");
        assert!(parameters.get("$schema").is_none());
        assert!(parameters.get("additionalProperties").is_none());
        assert_eq!(
            parameters["properties"]["additionalProperties"]["type"],
            "BOOLEAN"
        );
        assert_eq!(
            parameters["properties"]["city"],
            json!({"type":"STRING","nullable":true})
        );
        assert_eq!(
            request.body["toolConfig"]["functionCallingConfig"],
            json!({
                "mode":"ANY","allowedFunctionNames":["weather"]
            })
        );
        let config = &request.body["generationConfig"];
        assert_eq!(
            config,
            &json!({
                "maxOutputTokens":4096, "temperature":0.3, "topP":0.8, "stopSequences":["END"],
                "responseMimeType":"application/json",
                "responseSchema":{"type":"OBJECT","properties":{"temperature":{"type":"INTEGER"}},"required":["temperature"]},
                "thinkingConfig":{"thinkingBudget":1024}
            })
        );
        chat["messages"][2]["content"][1]["image_url"]["url"] =
            json!("https://example.com/photo.PNG?x=1");
        chat["stream"] = json!(false);
        assert!(translate::to_native(AiProvider::Gemini, "gemini-2.5-pro", &chat).is_err());
        let request =
            translate::to_native(AiProvider::Vertex, "gemini-3-flash-preview", &chat).unwrap();
        assert_eq!(
            request.rest_path,
            "v1/projects/-/locations/-/publishers/google/models/gemini-3-flash-preview:generateContent"
        );
        assert!(request.query.is_empty());
        assert_eq!(
            request.body["contents"][0]["parts"][1],
            json!({
                "fileData":{"mimeType":"image/png","fileUri":"https://example.com/photo.PNG?x=1"}
            })
        );
        assert_eq!(
            request.body["generationConfig"]["thinkingConfig"]["thinkingLevel"],
            "LOW"
        );
        chat["messages"][4]["tool_call_id"] = json!("unknown");
        assert!(translate::to_native(AiProvider::Vertex, "gemini-3-flash-preview", &chat).is_err());
    }

    #[test]
    fn translates_responses_and_stream_usage() {
        let events: Vec<Value> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/translate/gemini/stream.json"
        ))
        .unwrap();
        let mut stream = translate::stream_translator(Target::Gemini, "fast", "chat_123", 42, true);
        let mut chunks: Vec<_> = events
            .iter()
            .flat_map(|event| {
                stream.on_event(&SseEvent {
                    event: None,
                    data: event.to_string(),
                })
            })
            .collect();
        chunks.extend(stream.finish());
        assert_eq!(chunks.len(), 6);
        assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "Checking.");
        let tool = |index: usize| &chunks[index]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tool(2)["id"], "call_0");
        assert_eq!(tool(2)["thought_signature"], "YWJj");
        assert_eq!(tool(2)["function"]["arguments"], r#"{"city":"Paris"}"#);
        assert_eq!(tool(3)["index"], 1);
        assert_eq!(chunks[4]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chunks[5]["choices"], json!([]));
        assert_eq!(chunks[5]["usage"], openai::usage(20, 8, 4));
        assert!(stream.finish().is_empty());

        let response = translate::from_native(Target::Gemini, "fast", &events[1]);
        assert_eq!(response["model"], "fast");
        assert_eq!(
            response["choices"][0]["message"]["tool_calls"][1]["id"],
            "call_1"
        );
        assert_eq!(response["choices"][0]["finish_reason"], "tool_calls");
        for (reason, expected) in [
            ("STOP", "stop"),
            ("MAX_TOKENS", "length"),
            ("RECITATION", "content_filter"),
            ("SAFETY", "content_filter"),
            ("BLOCKLIST", "content_filter"),
            ("PROHIBITED_CONTENT", "content_filter"),
        ] {
            let native =
                json!({"candidates":[{"finishReason":reason,"content":{"parts":[{"text":"hi"}]}}]});
            let response = translate::from_native(Target::Gemini, "fast", &native);
            assert_eq!(response["choices"][0]["message"]["content"], "hi");
            assert_eq!(response["choices"][0]["finish_reason"], expected);
        }
    }
}
