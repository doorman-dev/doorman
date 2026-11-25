//! OpenAI chat ⇄ Anthropic Messages, including Vertex Claude.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

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
    let stream = chat["stream"].as_bool().unwrap_or_default();
    let vertex = provider == AiProvider::Vertex;
    let rest_path = if vertex {
        let method = if stream {
            "streamRawPredict"
        } else {
            "rawPredict"
        };
        format!(
            "v1/projects/-/locations/-/publishers/anthropic/models/{}:{method}",
            openai::path_segment(model),
        )
    } else {
        "v1/messages".into()
    };
    let max_tokens = openai::output_token_limit(chat)?.unwrap_or(4096);
    let mut system = Vec::new();
    let mut messages = Vec::new();
    for message in openai::array_field(chat, "messages")? {
        let role = message["role"].as_str().unwrap_or_default();
        let content = &message["content"];
        match role {
            "system" | "developer" => {
                let blocks = content_blocks(content)?;
                if blocks.iter().any(|block| block["type"] != "text") {
                    return Err(TranslateError(
                        "Anthropic system messages require text".into(),
                    ));
                }
                system.extend(blocks);
            }
            "tool" => {
                let id = openai::tool_result_id(message)?;
                let content = content_blocks(content)?;
                push_turn(
                    &mut messages,
                    "user",
                    vec![json!({
                        "type": "tool_result", "tool_use_id": id, "content": content,
                    })],
                )?;
            }
            "assistant" => {
                let mut blocks = content_blocks(content)?;
                for call in openai::array_field(message, "tool_calls")? {
                    let (id, name, input) = openai::tool_use(call)?;
                    blocks
                        .push(json!({"type": "tool_use", "id": id, "name": name, "input": input}));
                }
                push_turn(&mut messages, role, blocks)?;
            }
            _ => push_turn(&mut messages, role, content_blocks(content)?)?,
        }
    }
    if messages.is_empty() {
        return Err(TranslateError(
            "Anthropic requires at least one conversation message".into(),
        ));
    }
    let mut body = json!({"messages": messages, "max_tokens": max_tokens, "stream": stream});
    if !vertex {
        body["model"] = json!(model);
    }
    match openai::response_format(chat)? {
        ResponseFormat::Text => {}
        ResponseFormat::JsonObject => {
            system.push(text_block(openai::JSON_OBJECT_INSTRUCTION));
        }
        ResponseFormat::JsonSchema { schema, .. } => {
            body["output_config"] = json!({"format": {"type": "json_schema", "schema": schema}});
        }
    }
    if !system.is_empty() {
        body["system"] = json!(system);
    }
    if let Some(stop) = openai::stop_sequences(chat)? {
        body["stop_sequences"] = stop;
    }
    for field in ["temperature", "top_p"] {
        if let Some(value) = chat.get(field).filter(|value| !value.is_null()) {
            body[field] = value.clone();
        }
    }
    let choice = openai::tool_choice(chat)?;
    configure_tools(chat, &mut body, choice)?;
    let (thinking, effort) = thinking(model, chat, max_tokens)?;
    if let Some(thinking) = thinking {
        let disabled = thinking["type"] == "disabled";
        if !disabled
            && (matches!(choice, ToolChoice::Required | ToolChoice::Named(_))
                || !body["temperature"].is_null()
                || !body["top_p"].is_null())
        {
            return Err(TranslateError(
                "Anthropic thinking cannot be combined with forced tools or sampling settings"
                    .into(),
            ));
        }
        body["thinking"] = thinking;
    }
    if let Some(effort) = effort {
        if body["output_config"].is_null() {
            body["output_config"] = json!({});
        }
        body["output_config"]["effort"] = json!(effort);
    }
    Ok(NativeRequest {
        rest_path,
        query: Vec::new(),
        body,
        stream,
    })
}

fn text_block(text: &str) -> Value {
    json!({"type": "text", "text": text})
}

fn content_blocks(content: &Value) -> Result<Vec<Value>, TranslateError> {
    match content {
        Value::Null => Ok(Vec::new()),
        Value::String(text) if text.is_empty() => Ok(Vec::new()),
        Value::String(text) => Ok(vec![text_block(text)]),
        Value::Array(parts) => parts
            .iter()
            .map(|part| match part["type"].as_str() {
                Some("text") => part["text"]
                    .as_str()
                    .map(text_block)
                    .ok_or_else(|| TranslateError("text content parts require text".into())),
                Some("image_url") => {
                    let url = openai::image_url(part)?;
                    let source = if url.starts_with("data:") {
                        let (media_type, data) = openai::base64_image(url)?;
                        json!({"type": "base64", "media_type": media_type, "data": data})
                    } else {
                        openai::https_image(url)?;
                        json!({"type": "url", "url": url})
                    };
                    Ok(json!({"type": "image", "source": source}))
                }
                _ => Err(TranslateError(
                    "Anthropic supports text and image_url content parts".into(),
                )),
            })
            .collect(),
        _ => Err(TranslateError(
            "message content must be text or an array of content parts".into(),
        )),
    }
}

fn push_turn(
    messages: &mut Vec<Value>,
    role: &str,
    blocks: Vec<Value>,
) -> Result<(), TranslateError> {
    if blocks.is_empty() {
        return Err(TranslateError(
            "Anthropic conversation messages require content or tool calls".into(),
        ));
    }
    if let Some(last) = messages.last_mut().filter(|last| last["role"] == role) {
        if let Some(content) = last["content"].as_array_mut() {
            content.extend(blocks);
        }
    } else {
        messages.push(json!({"role": role, "content": blocks}));
    }
    Ok(())
}

fn configure_tools(
    chat: &Value,
    body: &mut Value,
    choice: ToolChoice<'_>,
) -> Result<(), TranslateError> {
    let mut tools = Vec::new();
    for tool in openai::array_field(chat, "tools")? {
        let (name, function) = openai::tool_definition(tool)?;
        let mut native = json!({
            "name": name,
            "input_schema": openai::tool_parameters(function),
        });
        if let Some(description) = function["description"].as_str() {
            native["description"] = json!(description);
        }
        tools.push(native);
    }
    if tools.is_empty() {
        return if matches!(choice, ToolChoice::Required | ToolChoice::Named(_)) {
            Err(TranslateError(
                "tool_choice requires at least one function tool".into(),
            ))
        } else {
            Ok(())
        };
    }
    body["tools"] = json!(tools);
    let disable_parallel = chat["parallel_tool_calls"] == false;
    let mut native = match choice {
        ToolChoice::Default if !disable_parallel => return Ok(()),
        ToolChoice::Default | ToolChoice::Auto => json!({"type": "auto"}),
        ToolChoice::None => json!({"type": "none"}),
        ToolChoice::Required => json!({"type": "any"}),
        ToolChoice::Named(name) => json!({"type": "tool", "name": name}),
    };
    if disable_parallel && choice != ToolChoice::None {
        native["disable_parallel_tool_use"] = json!(true);
    }
    body["tool_choice"] = native;
    Ok(())
}

pub(super) fn thinking<'a>(
    model: &str,
    chat: &'a Value,
    max_tokens: u64,
) -> Result<(Option<Value>, Option<&'a str>), TranslateError> {
    let Some(effort) = openai::reasoning_effort(chat)? else {
        return Ok((None, None));
    };
    let versioned_model = model.split_once("claude-").map(|(_, model)| model);
    let model_version = versioned_model.and_then(|model| {
        let mut parts = model.split(['-', '.', '@']);
        let family = parts.next()?;
        let major = parts.next()?.parse::<u16>().ok()?;
        let minor = parts
            .next()
            .and_then(|part| part.parse::<u16>().ok())
            .unwrap_or_default();
        Some((family, major, minor))
    });
    let adaptive = matches!(model_version, Some(("opus" | "sonnet", 4, 6..)))
        || matches!(
            model_version,
            Some(("opus" | "sonnet" | "haiku" | "fable" | "mythos", 5.., _))
        );
    if effort == "none" {
        return Ok((adaptive.then(|| json!({"type": "disabled"})), None));
    }
    if adaptive {
        if (effort == "xhigh" && matches!(model_version, Some((_, 4, 6))))
            || (effort == "max" && matches!(model_version, Some(("haiku", _, _))))
        {
            return Err(TranslateError(
                "This Anthropic model does not support the requested reasoning_effort".into(),
            ));
        }
        let effort = if effort == "minimal" { "low" } else { effort };
        return Ok((Some(json!({"type": "adaptive"})), Some(effort)));
    }
    let budget = match effort {
        "minimal" | "low" => 1024,
        "medium" => 2048,
        "high" => 3072,
        _ => {
            return Err(TranslateError(
                "This Anthropic model requires low, medium, or high reasoning_effort".into(),
            ));
        }
    };
    if max_tokens <= 1024 {
        return Err(TranslateError(
            "Anthropic thinking requires max_tokens greater than 1024".into(),
        ));
    }
    Ok((
        Some(json!({
            "type": "enabled", "budget_tokens": budget.min(max_tokens - 1),
        })),
        None,
    ))
}

fn usage(native: &Map<String, Value>) -> Value {
    let tokens = |key: &str| native.get(key).and_then(Value::as_u64).unwrap_or_default();
    let cached = tokens("cache_read_input_tokens");
    let prompt = tokens("input_tokens")
        .saturating_add(cached)
        .saturating_add(tokens("cache_creation_input_tokens"));
    openai::usage(prompt, tokens("output_tokens"), cached)
}

pub(super) fn from_native(requested_model: &str, native: &Value) -> Value {
    let mut text = String::new();
    let mut calls = Vec::new();
    for block in native["content"].as_array().into_iter().flatten() {
        match block["type"].as_str() {
            Some("text") => text.push_str(block["text"].as_str().unwrap_or_default()),
            Some("tool_use") => calls.push(openai::tool_call(
                block["id"].as_str().unwrap_or_default(),
                block["name"].as_str().unwrap_or_default(),
                &block["input"],
            )),
            _ => {}
        }
    }
    openai::completion(
        requested_model,
        native["id"].as_str(),
        text,
        calls,
        openai::finish_reason(native["stop_reason"].as_str()),
        native["usage"]
            .as_object()
            .map(usage)
            .unwrap_or_else(|| openai::usage(0, 0, 0)),
    )
}

pub(super) struct Chunks {
    meta: ChunkMeta,
    tool_indexes: HashMap<u64, usize>,
    usage: Map<String, Value>,
    started: bool,
    sent_finish: bool,
    closed: bool,
}

impl Chunks {
    pub(super) fn new(meta: ChunkMeta) -> Self {
        Self {
            meta,
            tool_indexes: HashMap::new(),
            usage: Map::new(),
            started: false,
            sent_finish: false,
            closed: false,
        }
    }

    fn content_start(&mut self, event: &Value) -> Option<Value> {
        let block = &event["content_block"];
        match block["type"].as_str()? {
            "text" => {
                let text = block["text"].as_str().filter(|text| !text.is_empty())?;
                Some(json!({"content": text}))
            }
            "tool_use" => {
                let index = event["index"].as_u64()?;
                let tool_index = self.tool_indexes.len();
                self.tool_indexes.insert(index, tool_index);
                let input = block["input"]
                    .as_object()
                    .filter(|input| !input.is_empty())
                    .map(|_| block["input"].to_string())
                    .unwrap_or_default();
                Some(json!({"tool_calls": [{
                    "index": tool_index, "id": block["id"], "type": "function",
                    "function": {"name": block["name"], "arguments": input},
                }]}))
            }
            _ => None,
        }
    }

    fn content_delta(&self, event: &Value) -> Option<Value> {
        let delta = &event["delta"];
        match delta["type"].as_str()? {
            "text_delta" => Some(json!({"content": delta["text"].as_str()?})),
            "input_json_delta" => {
                let index = self.tool_indexes.get(&event["index"].as_u64()?)?;
                Some(openai::tool_arguments_delta(
                    *index,
                    delta["partial_json"].as_str()?,
                ))
            }
            _ => None,
        }
    }

    fn update_usage(&mut self, usage: &Value) {
        if let Some(fields) = usage.as_object() {
            self.usage.extend(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
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
        match data["type"].as_str().or(event.event.as_deref()) {
            Some("message_start") => {
                self.update_usage(&data["message"]["usage"]);
                if self.started {
                    return Vec::new();
                }
                self.started = true;
                vec![self.meta.chunk(json!({"role": "assistant"}), None)]
            }
            Some("content_block_start") => self
                .content_start(&data)
                .map(|delta| self.meta.chunk(delta, None))
                .into_iter()
                .collect(),
            Some("content_block_delta") => self
                .content_delta(&data)
                .map(|delta| self.meta.chunk(delta, None))
                .into_iter()
                .collect(),
            Some("message_delta") => {
                self.update_usage(&data["usage"]);
                if let Some(reason) = data["delta"]["stop_reason"].as_str()
                    && !self.sent_finish
                {
                    self.sent_finish = true;
                    return vec![
                        self.meta
                            .chunk(json!({}), Some(openai::finish_reason(Some(reason)))),
                    ];
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn finish(&mut self) -> Vec<Value> {
        if self.closed {
            return Vec::new();
        }
        self.closed = true;
        let mut chunks = Vec::new();
        if !self.sent_finish {
            let reason = if self.tool_indexes.is_empty() {
                "stop"
            } else {
                "tool_calls"
            };
            chunks.push(self.meta.chunk(json!({}), Some(reason)));
        }
        if self.meta.include_usage {
            chunks.push(self.meta.usage_chunk(usage(&self.usage)));
        }
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::translate::{self, Target};

    #[test]
    fn translates_messages_images_and_vertex_paths() {
        let chat: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/translate/anthropic/request.json"
        ))
        .unwrap();
        let request =
            translate::to_native(AiProvider::Anthropic, "claude-haiku-4-5", &chat).unwrap();
        assert_eq!(request.rest_path, "v1/messages");
        assert!(request.stream && request.query.is_empty());
        assert_eq!(request.body["model"], "claude-haiku-4-5");
        assert_eq!(request.body["max_tokens"], 2048);
        assert_eq!(
            request.body["system"],
            json!([
                {"type":"text", "text":"Keep answers short."},
                {"type":"text", "text":"Use metric units."},
            ])
        );
        assert_eq!(request.body["messages"].as_array().unwrap().len(), 3);
        let first = &request.body["messages"][0];
        assert_eq!(first["content"][0], text_block("What is in the image?"));
        assert_eq!(first["content"][1]["source"]["type"], "base64");
        assert_eq!(first["content"][1]["source"]["media_type"], "image/png");
        let image = first["content"][1]["source"]["data"].as_str().unwrap();
        assert_eq!(
            format!("data:image/png;base64,{image}"),
            chat["messages"][3]["content"][0]["image_url"]["url"]
        );
        assert_eq!(
            first["content"][2]["source"],
            json!({"type":"url","url":"https://example.com/photo.jpeg"})
        );
        assert_eq!(request.body["stop_sequences"], json!(["END"]));
        assert_eq!(request.body["temperature"], 0.2);
        assert_eq!(request.body["top_p"], 0.8);
        assert!(request.body.get("user").is_none());

        let vertex =
            translate::to_native(AiProvider::Vertex, "claude-haiku-4-5@20251001", &chat).unwrap();
        assert_eq!(
            vertex.rest_path,
            "v1/projects/-/locations/-/publishers/anthropic/models/claude-haiku-4-5@20251001:streamRawPredict"
        );
        assert!(vertex.body.get("model").is_none());
        assert!(vertex.body.get("anthropic_version").is_none());
        let chat = json!({"messages":[{"role":"user","content":"hi"}]});
        let vertex = translate::to_native(AiProvider::Vertex, "claude-haiku-4-5", &chat).unwrap();
        assert!(vertex.rest_path.ends_with(":rawPredict"));
        assert_eq!(vertex.body["max_tokens"], 4096);
    }

    #[test]
    fn translates_tool_round_trip_and_usage() {
        let mut native: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/translate/anthropic/tool-reply.json"
        ))
        .unwrap();
        let response = translate::from_native(Target::Anthropic, "fast", &native);
        assert_eq!(response["model"], "fast");
        assert_eq!(response["id"], "msg_001");
        assert_eq!(response["usage"], openai::usage(60, 5, 10));
        let message = &response["choices"][0]["message"];
        assert_eq!(message["content"], "Checking now.");
        assert_eq!(
            message["tool_calls"][0]["function"]["arguments"],
            r#"{"city":"Paris"}"#
        );
        assert_eq!(response["choices"][0]["finish_reason"], "tool_calls");

        let mut chat = json!({
            "messages": [
                {"role":"user", "content":"Weather?"},
                message,
                {"role":"tool", "tool_call_id":"toolu_weather", "content":"Sunny"},
                {"role":"user", "content":"In Celsius, please."},
            ],
            "tools":[{"type":"function","function":{"name":"weather","description":"Get weather",
                "parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}],
            "tool_choice":{"type":"function","function":{"name":"weather"}},
            "parallel_tool_calls": false
        });
        let request = translate::to_native(AiProvider::Anthropic, "claude", &chat).unwrap();
        assert_eq!(request.body["tools"][0]["name"], "weather");
        assert_eq!(request.body["tools"][0]["description"], "Get weather");
        assert_eq!(
            request.body["tools"][0]["input_schema"]["properties"]["city"]["type"],
            "string"
        );
        assert_eq!(
            request.body["tool_choice"],
            json!({"type":"tool","name":"weather","disable_parallel_tool_use":true})
        );
        assert_eq!(
            request.body["messages"][1]["content"][1],
            native["content"][3]
        );
        assert_eq!(
            request.body["messages"][2]["content"],
            json!([
                {"type":"tool_result","tool_use_id":"toolu_weather","content":[{"type":"text","text":"Sunny"}]},
                {"type":"text","text":"In Celsius, please."},
            ])
        );
        chat["messages"][1]["tool_calls"][0]["function"]["arguments"] = json!("invalid");
        assert!(translate::to_native(AiProvider::Anthropic, "claude", &chat).is_err());

        for (stop, finish) in [
            ("end_turn", "stop"),
            ("stop_sequence", "stop"),
            ("max_tokens", "length"),
            ("refusal", "content_filter"),
        ] {
            native["stop_reason"] = json!(stop);
            let response = translate::from_native(Target::Anthropic, "fast", &native);
            assert_eq!(response["choices"][0]["finish_reason"], finish);
        }
    }

    #[test]
    fn maps_json_formats_effort_and_tool_choice() {
        let mut chat = json!({
            "messages":[{"role":"user","content":"Answer in JSON."}],
            "response_format":{"type":"json_object"},
            "reasoning_effort":"medium",
            "tools":[{"type":"function","function":{"name":"weather"}}],
            "tool_choice":"auto",
            "parallel_tool_calls":false
        });
        let request =
            translate::to_native(AiProvider::Anthropic, "claude-haiku-4-5", &chat).unwrap();
        assert_eq!(
            request.body["system"][0],
            text_block(openai::JSON_OBJECT_INSTRUCTION)
        );
        assert_eq!(
            request.body["thinking"],
            json!({"type":"enabled","budget_tokens":2048})
        );
        assert_eq!(
            request.body["tool_choice"],
            json!({"type":"auto","disable_parallel_tool_use":true})
        );
        chat["reasoning_effort"] = json!("minimal");
        chat["response_format"] = json!({"type":"json_schema","json_schema":{"name":"readout",
            "schema":{"type":"object","properties":{},"additionalProperties":false}}});
        let request =
            translate::to_native(AiProvider::Anthropic, "claude-opus-4-6", &chat).unwrap();
        assert_eq!(request.body["thinking"], json!({"type":"adaptive"}));
        assert_eq!(request.body["output_config"]["effort"], "low");
        assert_eq!(
            request.body["output_config"]["format"]["schema"],
            chat["response_format"]["json_schema"]["schema"]
        );
        chat["max_tokens"] = json!(1024);
        assert!(translate::to_native(AiProvider::Anthropic, "claude-haiku-4-5", &chat).is_err());
        chat["reasoning_effort"] = Value::Null;
        chat["tool_choice"] = json!("required");
        let request =
            translate::to_native(AiProvider::Anthropic, "claude-haiku-4-5", &chat).unwrap();
        assert_eq!(
            request.body["tool_choice"],
            json!({"type":"any","disable_parallel_tool_use":true})
        );
        chat["tool_choice"] = json!("none");
        let request =
            translate::to_native(AiProvider::Anthropic, "claude-haiku-4-5", &chat).unwrap();
        assert_eq!(request.body["tool_choice"], json!({"type":"none"}));
    }

    #[test]
    fn translates_stream_tool_indexes_and_usage() {
        let events: Vec<Value> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/translate/anthropic/stream.json"
        ))
        .unwrap();
        let mut stream =
            translate::stream_translator(Target::Anthropic, "fast", "chat_123", 42, true);
        let mut chunks: Vec<_> = events
            .iter()
            .flat_map(|event| {
                stream.on_event(&SseEvent {
                    event: event["type"].as_str().map(str::to_owned),
                    data: event.to_string(),
                })
            })
            .collect();
        chunks.extend(stream.finish());
        assert_eq!(chunks.len(), 9);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk["model"] == "fast" && chunk["id"] == "chat_123")
        );
        assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "Checking now.");
        let tool = |index: usize| &chunks[index]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tool(2)["id"], "toolu_weather");
        assert_eq!(tool(2)["index"], 0);
        assert_eq!(tool(3)["function"]["arguments"], r#"{"city":"#);
        assert_eq!(tool(4)["function"]["arguments"], r#""Paris"}"#);
        assert_eq!(tool(5)["index"], 1);
        assert_eq!(tool(6)["index"], 1);
        assert_eq!(chunks[7]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chunks[8]["choices"], json!([]));
        assert_eq!(chunks[8]["usage"], openai::usage(60, 5, 10));
        assert!(stream.finish().is_empty());
    }
}
