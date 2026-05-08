# pipeline_demos

A live demo repository for the **"From Prompt to Pipeline: How Dual-Agent Method Automates Cloud Security Remediation"** talk. It implements a patent-pending dual-agent agentic architecture that bridges the gap between security findings and real infrastructure remediation — fully automated through GitHub Actions and GitHub Models.

---

## How it works

The system operates through two specialized agents:

**Papaya** (Advisory Agent) — takes a plain-language security request, calls an LLM via the GitHub Models API, and translates it into a validated JSON handoff schema. It then triggers Kiwi automatically.

**Kiwi** (Executor Agent) — ingests the handoff schema, runs the appropriate security scans (container CVE scanning, Terraform IaC policy evaluation, live AWS cloud scanning), calls the LLM with the combined findings, and opens a Pull Request with Terraform remediations applied.

```
User prompt
    │
    ▼
┌─────────────────────────────────┐
│  Papaya  (workflow_dispatch)    │
│  · Calls GitHub Models (GPT-4o) │
│  · Outputs validated JSON       │
│  · Fires repository_dispatch    │
└────────────────┬────────────────┘
                 │  JSON handoff schema
                 ▼
┌─────────────────────────────────┐
│  Kiwi  (repository_dispatch)    │
│  · Grype  — container CVEs      │
│  · Checkov — Terraform IaC      │
│  · Prowler — live AWS cloud     │
│  · Calls GitHub Models (GPT-4o) │
│  · Opens remediation PR         │
└─────────────────────────────────┘
```

---

## Repository structure

```
.github/workflows/
  papaya-advisory.yml       # Papaya: advisory agent workflow
  kiwi-executor.yml         # Kiwi: executor agent workflow
  checkov.yml               # Standalone Checkov scan (on PR to tf/)
  Docker Image Scan.yml     # Standalone Grype container scan
  prowler.yml               # Standalone Prowler AWS scan
  trufflehog.yml            # Standalone TruffleHog secret scan

agents/
  handoff_schema.json       # JSON Schema draft-07 contract between Papaya and Kiwi
  papaya_system_prompt.md   # Papaya's LLM system prompt
  kiwi_system_prompt.md     # Kiwi's LLM system prompt + remediation rules
  remediate.py              # Kiwi's remediation execution script

tf/
  ec2_instance.tf           # AWS EC2 spot instance (intentional misconfigs for demo)
  s3.tf                     # AWS S3 bucket (intentional misconfigs for demo)
  google_compute_instance.tf # GCP VM instance (intentional misconfigs for demo)

Dockerfile                  # Python 3.11 slim app image
requirements.txt
```

---

## Setup

### Prerequisites
- A GitHub repository with Actions enabled
- GitHub Models access (available with any GitHub account at [github.com/marketplace/models](https://github.com/marketplace/models))
- For the Prowler cloud scan: AWS credentials stored as repository secrets

### Required secrets and variables

| Name | Type | Required for |
|------|------|-------------|
| `AWS_ACCESS_KEY_ID` | Secret | Prowler cloud scan |
| `AWS_SECRET_ACCESS_KEY` | Secret | Prowler cloud scan |
| `AWS_REGION` | Variable | Prowler cloud scan (defaults to `us-east-1`) |

> **No LLM secret needed.** Both Papaya and Kiwi authenticate to GitHub Models using the built-in `GITHUB_TOKEN`. No OpenAI key or other credential is required.

### One-time Actions configuration

In your repository go to **Settings → Actions → General** and enable:
- **Allow GitHub Actions to create and approve pull requests**

This is required for Kiwi to open the remediation PR.

---

## Running the live demo

### Step 1 — Trigger Papaya

Go to **Actions → Papaya - Advisory Agent → Run workflow**.

Enter a plain-language prompt, for example:
```
scan this container image and remediate any critical CVEs
```
or:
```
check all my infrastructure and fix any high severity findings
```

### Step 2 — Watch the handoff

In the Papaya workflow logs, look for the `PAPAYA OUTPUT` section. It shows the validated JSON handoff schema that Papaya produced from your prompt — including which scans to run, severity threshold, and remediation strategy.

Example handoff output:
```json
{
  "schema_version": "1.0",
  "request_id": "a3f1c2d4-...",
  "natural_language_prompt": "scan this container image and remediate any critical CVEs",
  "intent": "scan_and_remediate",
  "scan_targets": {
    "container": true,
    "iac": false,
    "cloud": false
  },
  "severity_threshold": "critical",
  "remediation": {
    "enabled": true,
    "strategy": "open_pr",
    "branch_prefix": "kiwi/remediation"
  }
}
```

### Step 3 — Kiwi fires automatically

A second workflow run — **Kiwi - Executor Agent** — appears in the Actions tab without any manual trigger. This is the `repository_dispatch` event fired by Papaya. Two distinct workflow runs visible simultaneously is the key demo moment.

### Step 4 — Scans run in parallel

Kiwi activates only the scan jobs indicated by the handoff schema:

| Job | Tool | What it scans |
|-----|------|---------------|
| `scan-container` | Grype | Docker image CVEs |
| `scan-iac` | Checkov | `tf/*.tf` Terraform files |
| `scan-cloud` | Prowler | Live AWS account |

The Terraform files in this repo contain intentional misconfigurations (no S3 encryption, no EC2 IMDSv2, GCP VM with public IP) so Checkov will always produce real findings for the demo.

### Step 5 — Remediation PR opens

Kiwi downloads all scan artifacts, calls GitHub Models with the findings and the current Terraform file contents, and applies the returned patches. A PR is opened on a branch named `kiwi/remediation-{run_id}` with:
- A findings table (Check ID, Resource, Severity, Fix Applied)
- Full description of each patch
- Complete updated `tf/*.tf` file contents

---

## Handoff schema

The JSON contract between Papaya and Kiwi is defined in [`agents/handoff_schema.json`](agents/handoff_schema.json) and validated with `jsonschema` at both ends. Key fields:

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `"1.0"` | Schema version, always `"1.0"` |
| `intent` | enum | `scan_and_remediate`, `scan_only`, or `remediate_only` |
| `scan_targets.container` | bool | Run Grype container scan |
| `scan_targets.iac` | bool | Run Checkov Terraform scan |
| `scan_targets.cloud` | bool | Run Prowler AWS scan |
| `severity_threshold` | enum | `critical`, `high`, `medium`, or `low` |
| `remediation.strategy` | enum | `open_pr`, `direct_push`, or `report_only` |

---

## Standalone scans

The original standalone scan workflows remain available and fire independently:

- **Checkov** — triggers on pull requests that modify `tf/**`
- **Docker Image Scan** — triggers on push to `main` and pull requests
- **Prowler** — triggers on push to `main` and pull requests (requires AWS secrets)
- **TruffleHog** — triggers on push to `main` and pull requests to scan the repo for leaked secrets, including workflow files under `.github/workflows/`

---

## Known demo findings

The Terraform files in `tf/` are intentionally under-configured to guarantee Checkov findings during the demo:

| File | Check | Issue |
|------|-------|-------|
| `tf/s3.tf` | CKV_AWS_21 | S3 bucket versioning not enabled |
| `tf/s3.tf` | CKV_AWS_145 | S3 bucket not encrypted with KMS |
| `tf/s3.tf` | CKV_AWS_18 | S3 access logging not configured |
| `tf/ec2_instance.tf` | CKV_AWS_172 | EC2 IMDSv2 not enforced |
| `tf/ec2_instance.tf` | CKV_AWS_8 | EC2 detailed monitoring disabled |
| `tf/google_compute_instance.tf` | CKV_GCP_38 | Shielded VM not enabled |
| `tf/google_compute_instance.tf` | CKV_GCP_40 | VM has a public IP address |
