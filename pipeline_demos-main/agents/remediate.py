#!/usr/bin/env python3
"""
Kiwi executor agent — remediation script.
Loads scan results, calls GitHub Models to draft Terraform patches, applies them.
Exit 0 = patched, 2 = nothing to patch, 1 = error.
"""

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

# ── Paths & config ─────────────────────────────────────────────────────────
ENDPOINT   = "https://models.inference.ai.azure.com/chat/completions"
MODEL      = os.environ.get("KIWI_MODEL", "openai/gpt-4.1-mini")
# Tried in order; first success wins (mirrors Papaya's fallback logic).
MODEL_CANDIDATES = [
    MODEL,
    "openai/gpt-4.1-mini",
    "openai/gpt-4o-mini",
    "gpt-4o-mini",
]
REPO       = pathlib.Path(__file__).parent.parent
TF_DIR     = REPO / "tf"
AGENTS_DIR = REPO / "agents"

# Standard output paths written by the scan jobs.
GRYPE_FILE    = REPO / "grype-results.json"
CHECKOV_FILE  = REPO / "checkov-results.json"
PROWLER_DIR   = REPO / "output"
OUT_FILE      = REPO / "kiwi-output.json"

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "unknown": 0}

# ── Loaders ────────────────────────────────────────────────────────────────

def load_json(path: pathlib.Path) -> list | dict | None:
    if not path or not path.exists():
        return None
    return json.loads(path.read_text())


def load_prowler_csv(directory: pathlib.Path) -> list | None:
    """Read all CSV files from Prowler output dir into a list of row dicts."""
    if not directory or not directory.exists():
        return None
    rows = []
    for csv_file in directory.glob("*.csv"):
        lines = csv_file.read_text().splitlines()
        if len(lines) < 2:
            continue
        headers = [h.strip().lower() for h in lines[0].split(";")]
        for line in lines[1:]:
            rows.append(dict(zip(headers, line.split(";"))))
    return rows or None

# ── Extractors ─────────────────────────────────────────────────────────────

def extract_grype(raw: dict | list | None, severity: str) -> list:
    if not raw:
        return []
    # anchore/scan-action may return a list; unwrap to the first element.
    if isinstance(raw, list):
        raw = raw[0] if raw else {}
    min_rank = SEV_RANK.get(severity.lower(), 3)
    # Native Grype JSON uses "matches"; scan-action may use "results" or "vulnerabilities".
    matches = raw.get("matches") or raw.get("results") or raw.get("vulnerabilities") or []
    findings = []
    for match in matches:
        v = match.get("vulnerability", match)  # flat format fallback
        sev = v.get("severity", "unknown").lower()
        if SEV_RANK.get(sev, 0) >= min_rank:
            findings.append({
                "id": v.get("id"),
                "severity": sev,
                "package": match.get("artifact", {}).get("name") or v.get("package"),
                "version": match.get("artifact", {}).get("version") or v.get("version"),
                "fix_versions": v.get("fix", {}).get("versions", []),
                "description": v.get("description", "")[:200],
            })
    return findings


def extract_checkov(raw: dict | list | None) -> list:
    if not raw:
        return []
    blocks = raw if isinstance(raw, list) else [raw]  # can be list or single block
    findings = []
    for block in blocks:
        for check in block.get("results", {}).get("failed_checks", []):
            findings.append({
                "check_id": check.get("check_id"),
                "check_type": check.get("check_type"),
                "resource": check.get("resource"),
                "file": check.get("file_path"),
                "guideline": check.get("guideline", ""),
            })
    return findings


def extract_prowler(rows: list | None, severity: str) -> list:
    if not rows:
        return []
    min_rank = SEV_RANK.get(severity.lower(), 3)
    return [
        {
            "check_id": r.get("check_id", "").strip(),
            "service": r.get("service_name", "").strip(),
            "resource": r.get("resource_uid", "").strip(),
            "severity": r.get("severity", "").strip().lower(),
            "detail": r.get("status_extended", "").strip(),
        }
        for r in rows
        if r.get("status", "").strip().upper() == "FAIL"
        and SEV_RANK.get(r.get("severity", "").strip().lower(), 0) >= min_rank
    ]

# ── LLM call ───────────────────────────────────────────────────────────────

def call_model(system: str, user: str, token: str) -> str:
    errors = []
    seen = []
    for model in MODEL_CANDIDATES:
        if model in seen:
            continue
        seen.append(model)
        base = {
            "model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user",   "content": user}],
            "temperature": 0.2,
        }
        for body in [{**base, "response_format": {"type": "json_object"}}, base]:
            req = urllib.request.Request(
                ENDPOINT,
                data=json.dumps(body).encode(),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    content = json.loads(r.read())["choices"][0]["message"]["content"]
                    if content:
                        print(f"[kiwi] Model success: {model}")
                        return content
            except urllib.error.HTTPError as e:
                err = e.read().decode(errors="replace")
                errors.append(f"{model} HTTP {e.code}: {err[:300]}")
                break  # don't retry same model without json_object mode on 4xx
            except Exception as e:
                errors.append(f"{model} {type(e).__name__}: {e}")
    raise RuntimeError("All model candidates failed:\n" + "\n".join(errors))

# ── Apply patches ──────────────────────────────────────────────────────────

def apply_patches(patches: list) -> int:
    applied = 0
    for patch in patches:
        target = REPO / patch.get("file", "")
        if not target.exists():
            print(f"[kiwi] Skipping missing file: {target}", file=sys.stderr)
            continue
        # Guard against path traversal
        try:
            target.resolve().relative_to(REPO.resolve())
        except ValueError:
            print(f"[kiwi] Refused path traversal: {target}", file=sys.stderr)
            continue
        target.write_text(patch.get("new_content", ""))
        print(f"[kiwi] Patched: {patch['file']}")
        applied += 1
    return applied

# ── Main ───────────────────────────────────────────────────────────────────

def main() -> int:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("::error::GITHUB_TOKEN not set.", file=sys.stderr)
        return 1

    severity = os.environ.get("SEVERITY", "high")

    # Extract findings from whichever scan artifacts exist.
    grype_f   = extract_grype(load_json(GRYPE_FILE), severity)
    checkov_f = extract_checkov(load_json(CHECKOV_FILE))
    prowler_f = extract_prowler(load_prowler_csv(PROWLER_DIR), severity)
    total = len(grype_f) + len(checkov_f) + len(prowler_f)
    print(f"[kiwi] Findings — grype:{len(grype_f)} checkov:{len(checkov_f)} prowler:{len(prowler_f)}")

    if total == 0:
        print("[kiwi] No findings at or above severity threshold.")
        return 2

    # Build the user message for the LLM.
    tf_files = {str(f.relative_to(REPO)): f.read_text() for f in sorted(TF_DIR.glob("*.tf"))}
    system   = (AGENTS_DIR / "kiwi_system_prompt.md").read_text()
    user_msg = json.dumps({
        "findings": {
            "grype":    grype_f   or None,
            "checkov":  checkov_f or None,
            "prowler":  prowler_f or None,
        },
        "terraform_files": tf_files,
        "severity_threshold": severity,
    }, indent=2)

    print(f"[kiwi] Calling {MODEL} for remediation plan...")
    try:
        raw = call_model(system, user_msg, token)
    except RuntimeError as e:
        print(f"::error::GitHub Models API call failed: {e}", file=sys.stderr)
        return 1

    try:
        output = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"::error::Model returned invalid JSON: {e}\n{raw[:2000]}", file=sys.stderr)
        return 1

    print("\n=== KIWI SUMMARY ===")
    print(output.get("summary", "(no summary)"))
    print("====================\n")

    OUT_FILE.write_text(json.dumps(output, indent=2))

    patches = output.get("patches", [])
    if not patches:
        print("[kiwi] No patches returned — nothing to remediate.")
        return 0

    applied = apply_patches(patches)
    print(f"[kiwi] Applied {applied}/{len(patches)} patches.")
    return 0 if applied > 0 else 2


if __name__ == "__main__":
    sys.exit(main())
