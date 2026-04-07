---
name: scan-skills
description: Scan skill files for prompt injection threats. Detects instruction override, role hijacking, context exfiltration, steganographic injection, dangerous operations, and social engineering attacks.
trigger: When the user asks to scan skills for security issues, detect prompt injection, or analyze skill safety.
---

# Prompt Injection Scanner

Scan skill files from ClawHub, Smithery, skills.sh and other sources for prompt injection threats.

## Usage

`/scan-skills [options]`

### Parameters

- `--path <dir>`: Directory containing skill files to scan (default: `./skills/`)
- `--output <dir>`: Report output directory (default: `./report/`)
- `--stage <1|2|full|full-llm>`: Run only a specific stage (default: `full`)
  - `1`: Rules engine only (fast, no LLM cost)
  - `2`: LLM semantic analysis only (no Stage 1)
  - `full`: Stage 1 on all skills; Stage 2 only when Stage 1 has findings or Stage TI is not CLEAN
  - `full-llm`: Stage 1 then Stage 2 on every skill (legacy “full” behavior)
- `--severity <critical|high|medium|all>`: Minimum severity to report (default: `all`)
- `--format <json|md|both>`: Output format (default: `both`)
- `--batch-size <n>`: Skills per LLM batch in Stage 2 (default: `5`)
- `--concurrency <n>`: Concurrent LLM requests (default: `3`)
- `--resume <scan_id>`: Resume a previously interrupted scan

### Examples

```bash
# Full scan of all skills
/scan-skills --path ./skills/

# Quick rules-only scan (no LLM cost)
/scan-skills --path ./skills/ --stage 1

# Scan with higher concurrency for faster Stage 2
/scan-skills --path ./skills/ --concurrency 5 --batch-size 10

# Resume an interrupted scan
/scan-skills --resume scan-20260310-143000-abc123
```

## Implementation

Run the scanner CLI:

```bash
cd /Users/kenshin/Workspace/skills-threat-analysis
python -m scanner.cli $ARGUMENTS
```
