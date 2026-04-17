#!/usr/bin/env python3
"""Patch OpenClaw config after container boot so that:
- anthropic-proxy (broken) is removed
- claude-direct uses anthropic-messages API
- groq plugin is allowed and enabled
- agent model has OpenRouter fallbacks so long-context 429s from claude-direct
  automatically failover to OpenRouter's Claude Sonnet / Haiku
"""
import json
import sys

CONFIG_PATH = "/data/.openclaw/openclaw.json"
FALLBACKS = [
    "openrouter/anthropic/claude-sonnet-4-6",
    "openrouter/anthropic/claude-haiku-4-5",
]

try:
    with open(CONFIG_PATH) as f:
        c = json.load(f)
except Exception as e:
    print(f"ERROR: cannot read config: {e}", file=sys.stderr)
    sys.exit(1)

changed = False

# --- models.providers -------------------------------------------------
providers = c.setdefault("models", {}).setdefault("providers", {})

if "anthropic-proxy" in providers:
    del providers["anthropic-proxy"]
    changed = True

if "claude-direct" in providers:
    p = providers["claude-direct"]
    if p.get("api") != "anthropic-messages":
        p["api"] = "anthropic-messages"
        changed = True
    if p.get("baseUrl") != "http://172.17.0.1:3456":
        p["baseUrl"] = "http://172.17.0.1:3456"
        changed = True
    for m in p.get("models", []):
        if isinstance(m.get("id"), str) and m["id"].startswith("anthropic/"):
            m["id"] = m["id"].replace("anthropic/", "", 1)
            changed = True

# --- plugins ----------------------------------------------------------
plugins = c.setdefault("plugins", {})
allow = plugins.setdefault("allow", [])
if "groq" not in allow:
    allow.append("groq")
    changed = True

entries = plugins.setdefault("entries", {})
groq_entry = entries.get("groq") or {}
if not groq_entry.get("enabled"):
    entries["groq"] = {"enabled": True, "config": groq_entry.get("config", {})}
    changed = True

# --- agents defaults: add failover to OpenRouter ---------------------
defaults = c.setdefault("agents", {}).setdefault("defaults", {})
model_def = defaults.setdefault("model", {})
if model_def.get("primary") != "claude-direct/claude-sonnet-4-6":
    model_def["primary"] = "claude-direct/claude-sonnet-4-6"
    changed = True
if model_def.get("fallbacks") != FALLBACKS:
    model_def["fallbacks"] = FALLBACKS
    changed = True

if changed:
    with open(CONFIG_PATH, "w") as f:
        json.dump(c, f, indent=2, ensure_ascii=False)
    print("Fixed")
else:
    print("OK")
