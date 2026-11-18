#!/usr/bin/env python3
"""Keyless model for the Doorman demo.

Answers with a canned reply and real-looking token usage, so the AI demo works
without a provider key. It is a stand-in for local testing only, not a model.

- OpenAI-compatible: /v1/models, /v1/chat/completions (plain and streaming).
- Amazon Bedrock: /model/{id}/converse, converse-stream, invoke,
  invoke-with-response-stream (AWS event-stream frames), count-tokens.
- Google Vertex AI: /v1/projects/{p}/locations/{l}/publishers/{google|anthropic}/
  models/{m}:generateContent, :streamGenerateContent, :rawPredict,
  :streamRawPredict, :countTokens, and a /token endpoint for the
  service-account exchange.

Credentials and SigV4 signatures are accepted without checking.
"""

from __future__ import annotations

import base64
import json
import os
import re
import struct
import time
import uuid
import zlib
from urllib.parse import unquote, urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("DEMO_LLM_HOST", "127.0.0.1")
PORT = int(os.environ.get("DEMO_LLM_PORT", "11435"))
REPLY = (
    "This answer came from Doorman's demo model. Your request was routed "
    "through the gateway, checked against your allowance and recorded in usage."
)


def tokens(text: str) -> int:
    return max(1, len(text.split()))


def prompt_tokens(body: dict) -> int:
    total = 0
    for message in body.get("messages") or []:
        content = message.get("content")
        if isinstance(content, list):
            content = " ".join(part.get("text", "") for part in content if isinstance(part, dict))
        total += tokens(str(content or ""))
    for part in body.get("system") or [] if isinstance(body.get("system"), list) else []:
        total += tokens(str(part.get("text", "")) if isinstance(part, dict) else "")
    for content in body.get("contents") or []:
        for part in content.get("parts") or []:
            total += tokens(str(part.get("text", "")))
    return total


def event_frame(headers: dict[str, str], payload: bytes) -> bytes:
    """One AWS event-stream message (string headers only)."""
    encoded = b""
    for name, value in headers.items():
        name_bytes, value_bytes = name.encode(), value.encode()
        encoded += struct.pack("!B", len(name_bytes)) + name_bytes
        encoded += struct.pack("!BH", 7, len(value_bytes)) + value_bytes
    total = 12 + len(encoded) + len(payload) + 4
    prelude = struct.pack("!II", total, len(encoded))
    prelude += struct.pack("!I", zlib.crc32(prelude) & 0xFFFFFFFF)
    message = prelude + encoded + payload
    return message + struct.pack("!I", zlib.crc32(message) & 0xFFFFFFFF)


def bedrock_event(event_type: str, value: dict) -> bytes:
    return event_frame(
        {":event-type": event_type, ":content-type": "application/json", ":message-type": "event"},
        json.dumps(value).encode(),
    )


def anthropic_message(model: str, usage: dict) -> dict:
    return {
        "id": f"msg_demo_{uuid.uuid4().hex[:12]}", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": REPLY}], "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": usage["input"], "output_tokens": usage["output"]},
    }


def anthropic_events(model: str, usage: dict) -> list[tuple[str, dict]]:
    message = anthropic_message(model, usage)
    message.update(content=[], stop_reason=None)
    message["usage"] = {"input_tokens": usage["input"], "output_tokens": 1}
    events = [("message_start", {"type": "message_start", "message": message}),
              ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})]
    for word in REPLY.split(" "):
        events.append(("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": word + " "}}))
    events += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
               ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": usage["output"]}}),
               ("message_stop", {"type": "message_stop"})]
    return events


def gemini_response(model: str, usage: dict, text: str = REPLY, final: bool = True) -> dict:
    candidate = {"content": {"role": "model", "parts": [{"text": text}]}, "index": 0}
    if final:
        candidate["finishReason"] = "STOP"
    reply = {"candidates": [candidate], "modelVersion": model}
    if final:
        reply["usageMetadata"] = {"promptTokenCount": usage["input"], "candidatesTokenCount": usage["output"],
                                  "totalTokenCount": usage["input"] + usage["output"]}
    return reply


BEDROCK_PATH = re.compile(r"^/model/(?P<model>[^/]+)/(?P<op>converse|converse-stream|invoke|invoke-with-response-stream|count-tokens)$")
VERTEX_PATH = re.compile(r"^/v1(?:beta1)?/projects/[^/]+/locations/[^/]+/publishers/(?P<publisher>google|anthropic)/models/(?P<model>[^/:]+):(?P<method>[A-Za-z]+)$")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[demo-llm] {self.command} {self.path} {args[1] if len(args) > 1 else ''}", flush=True)

    def send_json(self, status: int, value: dict) -> None:
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/v1/models":
            self.send_json(200, {"object": "list", "data": [{"id": "llama-demo", "object": "model", "owned_by": "doorman-demo"}]})
        elif self.path == "/health":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": {"message": "not found", "type": "invalid_request_error"}})

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length)
        if urlsplit(self.path).path == "/token":
            # Service-account exchange (form-encoded); any assertion is accepted.
            self.send_json(200, {"access_token": f"demo-vertex-token-{uuid.uuid4().hex[:8]}", "expires_in": 3600, "token_type": "Bearer"})
            return
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self.send_json(400, {"error": {"message": "invalid JSON", "type": "invalid_request_error"}})
            return
        url = urlsplit(self.path)
        if match := BEDROCK_PATH.match(url.path):
            self.bedrock(unquote(match["model"]), match["op"], body)
            return
        if match := VERTEX_PATH.match(url.path):
            alt_sse = parse_qs(url.query).get("alt") == ["sse"]
            self.vertex(match["publisher"], match["model"], match["method"], body, alt_sse)
            return
        if url.path.rstrip("/") != "/v1/chat/completions":
            self.send_json(404, {"error": {"message": "not found", "type": "invalid_request_error"}})
            return
        model = body.get("model") or "llama-demo"
        usage = {"prompt_tokens": prompt_tokens(body), "completion_tokens": tokens(REPLY)}
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
        reply_id = f"chatcmpl-demo-{uuid.uuid4().hex[:12]}"
        created = int(time.time())
        if not body.get("stream"):
            self.send_json(200, {
                "id": reply_id, "object": "chat.completion", "created": created, "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": REPLY}, "finish_reason": "stop"}],
                "usage": usage,
            })
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()

        def event(choices: list, extra: dict | None = None) -> None:
            chunk = {"id": reply_id, "object": "chat.completion.chunk", "created": created, "model": model, "choices": choices}
            chunk.update(extra or {})
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()

        event([{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}])
        for word in REPLY.split(" "):
            event([{"index": 0, "delta": {"content": word + " "}, "finish_reason": None}])
            time.sleep(0.03)
        event([{"index": 0, "delta": {}, "finish_reason": "stop"}])
        event([], {"usage": usage})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


    def start_stream(self, content_type: str) -> None:
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()
        self.close_connection = True

    def write(self, data: bytes) -> None:
        self.wfile.write(data)
        self.wfile.flush()
        time.sleep(0.03)

    def bedrock(self, model: str, op: str, body: dict) -> None:
        usage = {"input": prompt_tokens(body), "output": tokens(REPLY)}
        converse_usage = {"inputTokens": usage["input"], "outputTokens": usage["output"],
                          "totalTokens": usage["input"] + usage["output"]}
        if op == "count-tokens":
            inner = (body.get("input") or {})
            converse = inner.get("converse") or {}
            if "invokeModel" in inner:
                try:
                    converse = json.loads(base64.b64decode(inner["invokeModel"].get("body", "")))
                except ValueError:
                    converse = {}
            self.send_json(200, {"inputTokens": prompt_tokens(converse)})
        elif op == "converse":
            self.send_json(200, {
                "output": {"message": {"role": "assistant", "content": [{"text": REPLY}]}},
                "stopReason": "end_turn", "usage": converse_usage, "metrics": {"latencyMs": 120},
            })
        elif op == "invoke":
            self.send_json(200, anthropic_message(model, usage))
        elif op == "converse-stream":
            self.start_stream("application/vnd.amazon.eventstream")
            self.write(bedrock_event("messageStart", {"role": "assistant"}))
            for word in REPLY.split(" "):
                self.write(bedrock_event("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": word + " "}}))
            self.write(bedrock_event("contentBlockStop", {"contentBlockIndex": 0}))
            self.write(bedrock_event("messageStop", {"stopReason": "end_turn"}))
            self.write(bedrock_event("metadata", {"usage": converse_usage, "metrics": {"latencyMs": 120}}))
        else:
            self.start_stream("application/vnd.amazon.eventstream")
            events = anthropic_events(model, usage)
            for index, (_, event) in enumerate(events):
                if index == len(events) - 1:
                    event = dict(event, **{"amazon-bedrock-invocationMetrics": {
                        "inputTokenCount": usage["input"], "outputTokenCount": usage["output"],
                        "invocationLatency": 120, "firstByteLatency": 40}})
                chunk = {"bytes": base64.b64encode(json.dumps(event).encode()).decode()}
                self.write(bedrock_event("chunk", chunk))

    def vertex(self, publisher: str, model: str, method: str, body: dict, alt_sse: bool) -> None:
        usage = {"input": prompt_tokens(body), "output": tokens(REPLY)}
        if method == "countTokens":
            self.send_json(200, {"totalTokens": usage["input"]})
        elif publisher == "anthropic" and method == "rawPredict":
            if model == "count-tokens":
                self.send_json(200, {"input_tokens": usage["input"]})
            else:
                self.send_json(200, anthropic_message(model, usage))
        elif publisher == "anthropic" and method == "streamRawPredict":
            self.start_stream("text/event-stream")
            for name, event in anthropic_events(model, usage):
                self.write(f"event: {name}\ndata: {json.dumps(event)}\n\n".encode())
        elif publisher == "google" and method == "generateContent":
            self.send_json(200, gemini_response(model, usage))
        elif publisher == "google" and method == "streamGenerateContent":
            words = REPLY.split(" ")
            chunks = [gemini_response(model, usage, word + " ", final=index == len(words) - 1)
                      for index, word in enumerate(words)]
            if alt_sse:
                self.start_stream("text/event-stream")
                for chunk in chunks:
                    self.write(f"data: {json.dumps(chunk)}\r\n\r\n".encode())
            else:
                data = json.dumps(chunks).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        else:
            self.send_json(404, {"error": {"code": 404, "message": "not found", "status": "NOT_FOUND"}})


if __name__ == "__main__":
    print(f"[demo-llm] listening on http://{HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
