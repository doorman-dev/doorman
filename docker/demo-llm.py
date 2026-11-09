#!/usr/bin/env python3
"""Keyless OpenAI-compatible model for the Doorman demo.

Answers /v1/models and /v1/chat/completions (plain and streaming) with a
canned reply and real-looking token usage, so the AI demo works without a
provider key. It is a stand-in for local testing only, not a model.
"""

from __future__ import annotations

import json
import os
import time
import uuid
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
    return total


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
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_json(400, {"error": {"message": "invalid JSON", "type": "invalid_request_error"}})
            return
        if self.path.rstrip("/") != "/v1/chat/completions":
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


if __name__ == "__main__":
    print(f"[demo-llm] listening on http://{HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
