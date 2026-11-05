#!/usr/bin/env python3
"""Regenerate Doorman's built-in AI model prices from LiteLLM's public price list.

Run once per release:

    python3 scripts/update_ai_prices.py                 # downloads the latest list
    python3 scripts/update_ai_prices.py path/to/model_prices_and_context_window.json

Writes gateway-rs/src/ai/data/ai_prices.json. LiteLLM's price list is MIT
licensed (Copyright (c) 2023 Berri AI); the attribution is kept in the output.
Prices an admin enters in Doorman always override these.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
OUTPUT = Path(__file__).resolve().parent.parent / "gateway-rs" / "src" / "ai" / "data" / "ai_prices.json"

# LiteLLM provider -> (Doorman provider id, key prefix to strip).
PROVIDERS = {
    "openai": ("openai", ""),
    "anthropic": ("anthropic", ""),
    "gemini": ("gemini", "gemini/"),
    "azure": ("azure_openai", "azure/"),
    "bedrock_converse": ("bedrock", ""),
    "bedrock": ("bedrock", ""),
    "vertex_ai-language-models": ("vertex", "vertex_ai/"),
    "vertex_ai-anthropic_models": ("vertex", "vertex_ai/"),
}
TEXT_MODES = {"chat", "responses", "completion", None}


def per_million(value) -> int | float | None:
    """USD per token -> USD per million tokens, at most 6 decimal places.

    Written as a JSON number; its shortest form keeps the exact decimal the
    gateway parses (no floating-point billing happens in the gateway)."""
    if value is None:
        return None
    amount = (Decimal(str(value)) * 1_000_000).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    if amount < 0:
        return None
    amount = amount.normalize()
    return int(amount) if amount == amount.to_integral_value() else float(amount)


def load(path: str | None) -> dict:
    if path:
        return json.loads(Path(path).read_text())
    with urllib.request.urlopen(SOURCE_URL, timeout=60) as response:  # noqa: S310 (fixed https URL)
        return json.loads(response.read())


def build(source: dict) -> list[dict]:
    prices: dict[tuple[str, str], dict] = {}
    for key, entry in source.items():
        if not isinstance(entry, dict) or entry.get("mode") not in TEXT_MODES:
            continue
        mapping = PROVIDERS.get(entry.get("litellm_provider"))
        if not mapping:
            continue
        provider, prefix = mapping
        model = key[len(prefix):] if prefix and key.startswith(prefix) else key
        # Skip fine-tunes, regional/route-qualified names and anything with a wildcard.
        if model.startswith("ft:") or "*" in model or "/" in model:
            continue
        input_rate = per_million(entry.get("input_cost_per_token"))
        output_rate = per_million(entry.get("output_cost_per_token"))
        if input_rate is None or output_rate is None:
            continue
        row = {
            "provider": provider,
            "model_pattern": model,
            "input_usd_per_mtok": input_rate,
            "output_usd_per_mtok": output_rate,
            "cache_read_usd_per_mtok": per_million(entry.get("cache_read_input_token_cost")),
            "cache_write_usd_per_mtok": per_million(entry.get("cache_creation_input_token_cost")),
        }
        prices.setdefault((provider, model), row)
    return [prices[key] for key in sorted(prices)]


def main() -> None:
    source = load(sys.argv[1] if len(sys.argv) > 1 else None)
    prices = build(source)
    document = {
        "source": "LiteLLM model_prices_and_context_window.json",
        "source_url": SOURCE_URL,
        "license": "MIT, Copyright (c) 2023 Berri AI",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "prices": prices,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=1) + "\n")
    counts: dict[str, int] = {}
    for row in prices:
        counts[row["provider"]] = counts.get(row["provider"], 0) + 1
    print(f"wrote {len(prices)} prices to {OUTPUT} ({', '.join(f'{k} {v}' for k, v in sorted(counts.items()))})")


if __name__ == "__main__":
    main()
