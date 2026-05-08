#!/usr/bin/env python3
"""
Papaya advisory agent — model call script.

Reads USER_PROMPT and GITHUB_TOKEN from env, calls GitHub Models to
translate the plain-language prompt into a validated handoff schema JSON,
then writes it to papaya-handoff.json.

Falls back to a deterministic keyword parser if the API is unavailable.
Exit 0 on success, 1 on unrecoverable error.
"""

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request
import uuid

# ── Config ────────────────────────────────────────────────────────────────────
ENDPOINT = "https://models.inference.ai.azure.com/chat/completions"
OUT_FILE = pathlib.Path("papaya-handoff.json")

# Tried in order; first success wins.
MODEL_CANDIDATES = [
    "openai/gpt-4.1-mini",
    "openai/gpt-4o-mini",
    "openai/gpt-4o",
    "gpt-4o-mini",
    "gpt-4o",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def ask_model(token: str, system: str, user: str) -> str | None:
    """Try each model candidate; return content string or None."""
    errors = []
    for model in MODEL_CANDIDATES:
        base = {"model": model, "messages": [{"role": "system", "content": system},
                                              {"role": "user", "content": user}],
                "temperature": 0.1}
        # Try with and without forced JSON mode (not all models support it).
        for body in [{**base, "response_format": {"type": "json_object"}}, base]:
            req = urllib.request.Request(
                ENDPOINT,
                data=json.dumps(body).encode(),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=90) as r:
                    content = json.loads(r.read()).get("choices", [{}])[0].get("message", {}).get("content")
                    if content:
                        print(f"[papaya] Model success: {model}")
                        return content
            except urllib.error.HTTPError as e:
                errors.append(f"{model} HTTP {e.code}: {e.read().decode(errors='replace')[:300]}")
            except Exception as e:
                errors.append(f"{model} {type(e).__name__}: {e}")

    # Log all failures as warnings (not errors) so the step can continue.
    for err in errors:
        print(f"::warning::{err}")
    return None


def heuristic_handoff(prompt: str) -> dict:
    """Keyword-based fallback when the API is unavailable."""
    p = prompt.lower()

    if any(x in p for x in ["scan only", "only scan", "audit only"]):
        intent = "scan_only"
    elif any(x in p for x in ["fix only", "only fix", "remediate only"]):
        intent = "remediate_only"
    else:
        intent = "scan_and_remediate"

    broad = any(x in p for x in ["everything", "all", "full"])
    container = broad or any(x in p for x in ["container", "docker", "image", "cve"])
    iac       = broad or any(x in p for x in ["terraform", "iac", "infrastructure", "config", "policy"])
    cloud     = broad or any(x in p for x in ["aws", "cloud", "account", "live"])
    if not any([container, iac, cloud]):
        iac = True  # default to IaC scan

    if "critical" in p:        severity = "critical"
    elif "medium" in p:        severity = "medium"
    elif "low" in p:           severity = "low"
    else:                      severity = "high"

    return {
        "schema_version": "1.0",
        "request_id": str(uuid.uuid4()),
        "natural_language_prompt": prompt,
        "intent": intent,
        "scan_targets": {"container": container, "iac": iac, "cloud": cloud},
        "severity_threshold": severity,
        "remediation": {
            "enabled": intent != "scan_only",
            "strategy": "open_pr",
            "branch_prefix": "kiwi/remediation",
        },
    }

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "")
    prompt = os.environ.get("USER_PROMPT", "").strip()
    if not prompt:
        print("::error::USER_PROMPT is empty.", file=sys.stderr)
        return 1

    system = (pathlib.Path(__file__).parent / "papaya_system_prompt.md").read_text()

    raw = ask_model(token, system, prompt) if token else None

    if raw:
        # Parse model response
        try:
            handoff = json.loads(raw)
        except json.JSONDecodeError:
            print("::warning::Model returned non-JSON; using fallback parser.")
            handoff = heuristic_handoff(prompt)
    else:
        print("::warning::No model response; using fallback parser.")
        handoff = heuristic_handoff(prompt)

    OUT_FILE.write_text(json.dumps(handoff, indent=2))
    print(f"[papaya] Handoff written to {OUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
