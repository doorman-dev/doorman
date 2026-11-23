//! OpenAI chat ⇄ Bedrock Converse.

use std::collections::HashMap;

use serde_json::{Value, json};

use super::{
    ChunkTranslator, NativeRequest, TranslateError, anthropic,
    openai::{self, ChunkMeta, ResponseFormat, ToolChoice},
};
use crate::ai::sse::SseEvent;

pub(super) fn to_native(model: &str, chat: &Value) -> Result<NativeRequest, TranslateError> {
    let stream = chat["stream"].as_bool().unwrap_or_default();
    let action = if stream {
        "converse-stream"
    } else {
        "converse"
    };
    let path = format!("model/{}/{action}", openai::path_segment(model));
    let mut system = Vec::new();
    let mut messages = Vec::new();
    for message in openai::array_field(chat, "messages")? {
        let role = message["role"].as_str().unwrap_or_default();
        let content = &message["content"];
        match role {
            "system" | "developer" => {
                let blocks = content_blocks(content)?;
                if blocks.iter().any(|block| block.get("text").is_none()) {
                    return Err(TranslateError(
                        "Bedrock system messages require text".into(),
                    ));
                }
                system.extend(blocks);
            }
            "tool" => {
                let id = openai::tool_result_id(message)?;
                let result = tool_result(content)?;
                push_message(
                    &mut messages,
                    "user",
                    vec![json!({
                        "toolResult": {"toolUseId": id, "content": result}
                    })],
                )?;
            }
            "assistant" => {
                let mut blocks = content_blocks(content)?;
                for call in openai::array_field(message, "tool_calls")? {
                    let (id, name, input) = openai::tool_use(call)?;
                    blocks
                        .push(json!({"toolUse": {"toolUseId": id, "name": name, "input": input}}));
                }
                push_message(&mut messages, role, blocks)?;
            }
            _ => push_message(&mut messages, "user", content_blocks(content)?)?,
        }
    }
    if messages.is_empty() {
        return Err(TranslateError(
            "Bedrock requires at least one conversation message".into(),
        ));
    }

    let mut body = json!({"messages": messages});
    match openai::response_format(chat)? {
        ResponseFormat::Text => {}
        ResponseFormat::JsonObject => system.push(json!({"text": openai::JSON_OBJECT_INSTRUCTION})),
        ResponseFormat::JsonSchema {
            name,
            description,
            schema,
        } => {
            let mut definition =
                json!({"name": name.unwrap_or("response"), "schema": schema.to_string()});
            if let Some(description) = description {
                definition["description"] = json!(description);
            }
            body["outputConfig"] = json!({
                "textFormat": {"type": "json_schema", "structure": {"jsonSchema": definition}},
            });
        }
    }
    if !system.is_empty() {
        body["system"] = json!(system);
    }
    let max_tokens = openai::output_token_limit(chat)?;
    let mut inference = json!({});
    if let Some(limit) = max_tokens {
        inference["maxTokens"] = json!(limit);
    }
    if let Some(stop) = openai::stop_sequences(chat)? {
        inference["stopSequences"] = stop;
    }
    for (source, target) in [("temperature", "temperature"), ("top_p", "topP")] {
        if let Some(value) = chat.get(source).filter(|value| !value.is_null()) {
            inference[target] = value.clone();
        }
    }
    let choice = openai::tool_choice(chat)?;
    configure_tools(chat, &mut body, choice)?;
    if let Some(effort) = openai::reasoning_effort(chat)? {
        body["additionalModelRequestFields"] =
            reasoning(model, chat, effort, choice, &mut inference)?;
    }
    if inference != json!({}) {
        body["inferenceConfig"] = inference;
    }
    Ok(NativeRequest {
        rest_path: path,
        query: Vec::new(),
        body,
        stream,
    })
}

fn push_message(
    messages: &mut Vec<Value>,
    role: &str,
    blocks: Vec<Value>,
) -> Result<(), TranslateError> {
    if blocks.is_empty() {
        return Err(TranslateError(
            "Bedrock conversation messages require content or tool calls".into(),
        ));
    }
    if let Some(previous) = messages
        .last_mut()
        .filter(|message| message["role"] == role)
        && let Some(content) = previous["content"].as_array_mut()
    {
        content.extend(blocks);
    } else {
        messages.push(json!({"role": role, "content": blocks}));
    }
    Ok(())
}

fn content_blocks(content: &Value) -> Result<Vec<Value>, TranslateError> {
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
                Some("image_url") => {
                    let url = openai::image_url(part)?;
                    if !url.starts_with("data:") {
                        return Err(TranslateError(
                            "Bedrock Converse requires inline base64 image data URLs".into(),
                        ));
                    }
                    let (mime, data) = openai::base64_image(url)?;
                    let format = match mime {
                        "image/jpeg" | "image/jpg" => "jpeg",
                        "image/png" => "png",
                        "image/gif" => "gif",
                        "image/webp" => "webp",
                        _ => {
                            return Err(TranslateError(
                                "Bedrock images must be JPEG, PNG, GIF, or WebP".into(),
                            ));
                        }
                    };
                    Ok(json!({"image": {"format": format, "source": {"bytes": data}}}))
                }
                _ => Err(TranslateError(
                    "Bedrock supports text and image_url content parts".into(),
                )),
            })
            .collect(),
        _ => Err(TranslateError(
            "message content must be text or an array of content parts".into(),
        )),
    }
}

fn tool_result(content: &Value) -> Result<Vec<Value>, TranslateError> {
    let blocks = content_blocks(content)?;
    let mut result = Vec::new();
    for block in blocks {
        let text = block["text"]
            .as_str()
            .ok_or_else(|| TranslateError("Bedrock tool messages require text or JSON".into()))?;
        match serde_json::from_str::<Value>(text) {
            Ok(value) => result.push(json!({"json": value})),
            Err(_) => result.push(block),
        }
    }
    if result.is_empty() {
        return Err(TranslateError(
            "Bedrock tool messages require a result".into(),
        ));
    }
    Ok(result)
}

fn configure_tools(
    chat: &Value,
    body: &mut Value,
    choice: ToolChoice<'_>,
) -> Result<(), TranslateError> {
    if choice == ToolChoice::None {
        return Ok(());
    }
    let mut tools = Vec::new();
    for tool in openai::array_field(chat, "tools")? {
        let (name, function) = openai::tool_definition(tool)?;
        let mut spec =
            json!({"name": name, "inputSchema": {"json": openai::tool_parameters(function)}});
        if let Some(description) = function["description"].as_str() {
            spec["description"] = json!(description);
        }
        tools.push(json!({"toolSpec": spec}));
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
    body["toolConfig"] = json!({"tools": tools});
    let native = match choice {
        ToolChoice::Default | ToolChoice::None => return Ok(()),
        ToolChoice::Auto => json!({"auto": {}}),
        ToolChoice::Required => json!({"any": {}}),
        ToolChoice::Named(name) => json!({"tool": {"name": name}}),
    };
    body["toolConfig"]["toolChoice"] = native;
    Ok(())
}

fn reasoning(
    model: &str,
    chat: &Value,
    effort: &str,
    tool_choice: ToolChoice<'_>,
    inference: &mut Value,
) -> Result<Value, TranslateError> {
    if model.contains("anthropic.claude-") {
        let max_tokens = inference["maxTokens"].as_u64().unwrap_or(4096);
        let (thinking, native_effort) = anthropic::thinking(model, chat, max_tokens)?;
        let mut fields = json!({});
        if let Some(thinking) = thinking {
            if thinking["type"] != "disabled"
                && (matches!(tool_choice, ToolChoice::Required | ToolChoice::Named(_))
                    || !inference["temperature"].is_null()
                    || !inference["topP"].is_null())
            {
                return Err(TranslateError(
                    "Claude thinking on Bedrock cannot be combined with forced tools or sampling settings".into(),
                ));
            }
            if thinking["type"] == "enabled" {
                inference["maxTokens"] = json!(max_tokens);
            }
            fields["thinking"] = thinking;
        }
        if let Some(effort) = native_effort {
            fields["output_config"] = json!({"effort": effort});
        }
        return Ok(fields);
    }
    if model.contains("amazon.nova-2") {
        let level = match effort {
            "none" => return Ok(json!({"reasoningConfig": {"type": "disabled"}})),
            "minimal" | "low" => "low",
            "medium" => "medium",
            _ => "high",
        };
        if level == "high"
            && ["temperature", "topP", "maxTokens"]
                .iter()
                .any(|key| !inference[*key].is_null())
        {
            return Err(TranslateError(
                "High Nova reasoning cannot be combined with temperature, top_p, or a token limit"
                    .into(),
            ));
        }
        return Ok(json!({"reasoningConfig": {"type": "enabled", "maxReasoningEffort": level}}));
    }
    Err(TranslateError(
        "This Bedrock model has no supported reasoning_effort mapping".into(),
    ))
}

fn usage(native: &Value) -> Value {
    let tokens = |key: &str| native[key].as_u64().unwrap_or_default();
    let cached = tokens("cacheReadInputTokens");
    // Converse inputTokens excludes both cache reads and writes.
    // https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-caching.html
    let prompt = tokens("inputTokens")
        .saturating_add(cached)
        .saturating_add(tokens("cacheWriteInputTokens"));
    openai::usage(prompt, tokens("outputTokens"), cached)
}

pub(super) fn from_native(requested_model: &str, native: &Value) -> Value {
    let mut text = String::new();
    let mut calls = Vec::new();
    for block in native["output"]["message"]["content"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(value) = block["text"].as_str() {
            text.push_str(value);
        } else if let Some(tool) = block.get("toolUse") {
            calls.push(openai::tool_call(
                tool["toolUseId"].as_str().unwrap_or_default(),
                tool["name"].as_str().unwrap_or_default(),
                &tool["input"],
            ));
        }
    }
    openai::completion(
        requested_model,
        None,
        text,
        calls,
        openai::finish_reason(native["stopReason"].as_str()),
        usage(&native["usage"]),
    )
}

pub(super) struct Chunks {
    meta: ChunkMeta,
    tool_indexes: HashMap<u64, usize>,
    usage: Value,
    started: bool,
    sent_finish: bool,
    closed: bool,
}

impl Chunks {
    pub(super) fn new(meta: ChunkMeta) -> Self {
        Self {
            meta,
            tool_indexes: HashMap::new(),
            usage: usage(&Value::Null),
            started: false,
            sent_finish: false,
            closed: false,
        }
    }

    fn tool_start(&mut self, event: &Value) -> Option<Value> {
        let tool = &event["start"]["toolUse"];
        let block = event["contentBlockIndex"].as_u64()?;
        let id = tool["toolUseId"].as_str()?;
        let name = tool["name"].as_str()?;
        let index = self.tool_indexes.len();
        self.tool_indexes.insert(block, index);
        Some(json!({"tool_calls": [{
            "index": index, "id": id, "type": "function", "function": {"name": name, "arguments": ""},
        }]}))
    }

    fn content_delta(&self, event: &Value) -> Option<Value> {
        let delta = &event["delta"];
        if let Some(text) = delta["text"].as_str() {
            return Some(json!({"content": text}));
        }
        let index = self
            .tool_indexes
            .get(&event["contentBlockIndex"].as_u64()?)?;
        Some(openai::tool_arguments_delta(
            *index,
            delta["toolUse"]["input"].as_str()?,
        ))
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
        let delta = match event.event.as_deref() {
            Some("messageStart") if !self.started => {
                self.started = true;
                Some(json!({"role": "assistant"}))
            }
            Some("contentBlockStart") => self.tool_start(&data),
            Some("contentBlockDelta") => self.content_delta(&data),
            Some("messageStop") if !self.sent_finish => {
                self.sent_finish = true;
                let reason = openai::finish_reason(data["stopReason"].as_str());
                return vec![self.meta.chunk(json!({}), Some(reason))];
            }
            Some("metadata") => {
                self.usage = usage(&data["usage"]);
                None
            }
            _ => None,
        };
        delta
            .map(|delta| self.meta.chunk(delta, None))
            .into_iter()
            .collect()
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
            chunks.push(self.meta.usage_chunk(std::mem::take(&mut self.usage)));
        }
        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::{
        eventstream,
        translate::{self, Target},
    };

    #[test]
    fn translates_converse_tool_history_images_and_usage() {
        let mut native: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/translate/converse/reply.json"
        ))
        .unwrap();
        let completion = translate::from_native(Target::Converse, "fast", &native);
        assert_eq!(completion["model"], "fast");
        assert_eq!(completion["choices"][0]["finish_reason"], "tool_calls");
        let message = &completion["choices"][0]["message"];
        assert_eq!(message["content"], "Checking.");
        assert_eq!(
            message["tool_calls"][0]["function"]["arguments"],
            r#"{"city":"Paris"}"#
        );
        assert_eq!(completion["usage"], openai::usage(45, 8, 10));

        let mut chat = json!({
            "messages": [
                {"role":"system","content":"Be concise."},
                {"role":"developer","content":"Use Celsius."},
                {"role":"user","content":[{"type":"text","text":"Weather?"},{"type":"image_url",
                    "image_url":{"url":"data:image/png;base64,AA=="}}]},
                message,
                {"role":"tool","tool_call_id":"tool_weather","content":"{\"temperature\":18}"},
                {"role":"user","content":"Where?"}
            ],
            "tools":[{"type":"function","function":{"name":"weather","description":"Get weather",
                "parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}],
            "tool_choice":{"type":"function","function":{"name":"weather"}},
            "max_tokens":512,"temperature":0.2,"top_p":0.8,"stop":"END","stream":true
        });
        let model = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-haiku-4-5-v1:0";
        let request =
            translate::to_native(crate::ai::adapter::AiProvider::Bedrock, model, &chat).unwrap();
        assert_eq!(
            request.rest_path,
            "model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-haiku-4-5-v1%3A0/converse-stream"
        );
        assert!(request.stream && request.query.is_empty());
        assert!(request.body.get("model").is_none());
        assert_eq!(
            request.body["system"],
            json!([{"text":"Be concise."},{"text":"Use Celsius."}])
        );
        assert_eq!(
            request.body["inferenceConfig"],
            json!({
                "maxTokens":512,"temperature":0.2,"topP":0.8,"stopSequences":["END"]
            })
        );
        let messages = &request.body["messages"];
        assert_eq!(
            messages[0]["content"][1],
            json!({"image":{"format":"png","source":{"bytes":"AA=="}}})
        );
        assert_eq!(
            messages[1]["content"][1],
            native["output"]["message"]["content"][2]
        );
        assert_eq!(
            messages[2]["content"],
            json!([
                {"toolResult":{"toolUseId":"tool_weather","content":[{"json":{"temperature":18}}]}},
                {"text":"Where?"}
            ])
        );
        assert_eq!(
            request.body["toolConfig"]["toolChoice"],
            json!({"tool":{"name":"weather"}})
        );
        assert_eq!(
            request.body["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["type"],
            "object"
        );
        chat["messages"][2]["content"][1]["image_url"]["url"] =
            json!("https://example.com/photo.png");
        assert!(to_native(model, &chat).is_err());
        for (reason, expected) in [
            ("end_turn", "stop"),
            ("stop_sequence", "stop"),
            ("max_tokens", "length"),
            ("guardrail_intervened", "content_filter"),
            ("content_filtered", "content_filter"),
        ] {
            native["stopReason"] = json!(reason);
            assert_eq!(
                from_native("fast", &native)["choices"][0]["finish_reason"],
                expected
            );
        }
    }

    #[test]
    fn maps_converse_options_and_reasoning() {
        let mut chat = json!({
            "messages":[{"role":"user","content":"Respond in JSON."}],
            "tools":[{"type":"function","function":{"name":"weather"}}],
            "tool_choice":"none",
            "response_format":{"type":"json_schema","json_schema":{"name":"readout","description":"A report",
                "schema":{"type":"object","properties":{},"additionalProperties":false}}},
            "reasoning_effort":"medium"
        });
        let nova = "us.amazon.nova-2-lite-v1:0";
        let request = to_native(nova, &chat).unwrap();
        assert!(request.rest_path.ends_with("/converse"));
        assert!(request.body.get("toolConfig").is_none());
        assert_eq!(
            request.body["additionalModelRequestFields"],
            json!({
                "reasoningConfig":{"type":"enabled","maxReasoningEffort":"medium"}
            })
        );
        let format = &request.body["outputConfig"]["textFormat"]["structure"]["jsonSchema"];
        assert_eq!(format["name"], "readout");
        assert_eq!(format["description"], "A report");
        let schema: Value = serde_json::from_str(format["schema"].as_str().unwrap()).unwrap();
        assert_eq!(schema, chat["response_format"]["json_schema"]["schema"]);

        chat["tool_choice"] = json!("auto");
        chat["response_format"] = json!({"type":"json_object"});
        chat["reasoning_effort"] = json!("low");
        let request = to_native("us.anthropic.claude-haiku-4-5-v1:0", &chat).unwrap();
        assert_eq!(request.body["toolConfig"]["toolChoice"], json!({"auto":{}}));
        assert_eq!(
            request.body["system"][0]["text"],
            openai::JSON_OBJECT_INSTRUCTION
        );
        assert_eq!(
            request.body["additionalModelRequestFields"]["thinking"],
            json!({
                "type":"enabled","budget_tokens":1024
            })
        );
        assert_eq!(request.body["inferenceConfig"]["maxTokens"], 4096);
        chat["tool_choice"] = json!("required");
        chat["reasoning_effort"] = Value::Null;
        let request = to_native(nova, &chat).unwrap();
        assert_eq!(request.body["toolConfig"]["toolChoice"], json!({"any":{}}));
        chat["reasoning_effort"] = json!("high");
        chat["max_tokens"] = json!(1024);
        assert!(to_native(nova, &chat).is_err());
    }

    #[test]
    fn translates_converse_aws_stream_frames() {
        let events: Vec<Value> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/translate/converse/stream.json"
        ))
        .unwrap();
        let mut bytes = Vec::new();
        for event in events {
            let event_type = event["event"].as_str().unwrap();
            bytes.extend(eventstream::encode(
                &[(":message-type", "event"), (":event-type", event_type)],
                event["data"].to_string().as_bytes(),
            ));
        }
        bytes.extend(eventstream::encode(
            &[
                (":message-type", "exception"),
                (":exception-type", "modelStreamErrorException"),
            ],
            br#"{"message":"Provider error"}"#,
        ));
        let mut decoder = eventstream::Decoder::new(16384);
        let mut stream = translate::stream_translator(Target::Converse, "fast", "id", 42, true);
        let mut chunks = Vec::new();
        for frame in bytes.chunks(17).flat_map(|chunk| decoder.push(chunk)) {
            chunks.extend(stream.on_event(&frame.unwrap().to_sse_event()));
        }
        chunks.extend(stream.finish());
        assert_eq!(chunks.len(), 7);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk["id"] == "id" && chunk["model"] == "fast")
        );
        assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "Checking.");
        let call = |index: usize| &chunks[index]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(call(2)["id"], "tool_weather");
        assert_eq!(call(2)["index"], 0);
        assert_eq!(call(3)["function"]["arguments"], r#"{"city":"#);
        assert_eq!(call(4)["function"]["arguments"], r#""Paris"}"#);
        assert_eq!(chunks[5]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chunks[6]["choices"], json!([]));
        assert_eq!(chunks[6]["usage"], openai::usage(45, 8, 10));
    }
}
