# Skills Threat Analysis

A prompt injection and malicious behavior scanner for Claude Code skills from ClawHub, Smithery, skills.sh and other sources.

## Overview

With the rapid growth of community-contributed skills (~100k+), there is an increasing risk of malicious skills embedding prompt injection attacks, credential theft, data exfiltration, and other threats. This tool automates the detection of such threats through a four-stage scanning pipeline.

### Threat Categories

| Category | Description | Rules |
|----------|-------------|-------|
| Prompt Injection | Instruction override, role hijacking, system prompt manipulation | PI-001, PI-002, PI-003 |
| Command Injection | Dangerous shell commands, risky execution guidance, dynamic code execution | PI-006, PI-018, PI-021 |
| Social Engineering | Authority/urgency manipulation, trust exploitation, secrecy demands, operator-guided execution | PI-007, PI-019 |
| Data Exfiltration | Context/system prompt extraction, network exfiltration, SVG/XSS browser data theft | PI-004, PI-009, PI-017 |
| Hardcoded Secrets | Credential file access, API key exposure, bearer tokens | PI-008 |
| Obfuscation | Zero-width chars, base64 encoding, Unicode steganography | PI-005, PI-011 |
| Privilege Escalation | setuid/setgid abuse, sudoers modification, chmod +s | PI-014 |
| Persistence | Crontab, systemctl, LaunchAgent, pm2 persistence mechanisms | PI-013 |
| Filesystem Destruction | rm -rf, shutil.rmtree, fs.unlink patterns | PI-010 |
| Crypto Wallet Access | Wallet file access, seed phrase extraction, web3 key operations | PI-012 |
| Supply Chain Attack | Remote binary download, risky binary installation, download-and-execute droppers | PI-016, PI-020 |
| Trigger Hijacking | Auto-execution demands, exclusivity hijacking of other skills | PI-015 |

### Stage 1 Detection Rules (21 rules)

| Rule ID | Name | Severity | Language |
|---------|------|----------|----------|
| PI-001 | Instruction Override | HIGH | EN + ZH |
| PI-002 | Role Hijacking | HIGH | EN + ZH |
| PI-003 | System Prompt Manipulation | HIGH | EN + ZH |
| PI-004 | Context Exfiltration | HIGH | EN |
| PI-005 | Steganographic Injection | HIGH | * |
| PI-006 | Dangerous Operation | CRITICAL | EN + ZH |
| PI-007 | Social Engineering Injection | MEDIUM | EN + ZH |
| PI-008 | Credential Access | HIGH | * |
| PI-009 | Network Exfiltration | MEDIUM | * |
| PI-010 | Filesystem Destruction | HIGH | * |
| PI-011 | Obfuscation Standalone | LOW | * |
| PI-012 | Crypto Wallet Access | HIGH | * |
| PI-013 | Persistence Mechanism | HIGH | * |
| PI-014 | Privilege Escalation | HIGH | * |
| PI-015 | Trigger Hijacking | HIGH | EN + ZH |
| PI-016 | Remote Binary Download | CRITICAL | * |
| PI-017 | SVG / HTML XSS | CRITICAL | * |
| PI-018 | Risky Command Guidance | HIGH | EN |
| PI-019 | Operator-Guided Execution | HIGH | EN |
| PI-020 | Risky Binary Installation | HIGH | EN + ZH |
| PI-021 | Dynamic Code Execution | HIGH | EN |

### Stage 2 LLM Threat Categories

Stage 2 uses LLM semantic analysis to detect 17 threat categories:

`prompt_injection`, `command_injection`, `data_exfiltration`, `hardcoded_secrets`, `unauthorized_tool_use`, `obfuscation`, `social_engineering`, `resource_abuse`, `supply_chain_attack`, `privilege_escalation`, `malicious_guidance`, `skill_md_mismatch`, `code_quality`, `bytecode_tampering`, `trigger_hijacking`, `unicode_steganography`, `transitive_trust_abuse`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  /scan-skills (entry)                   │
└──────────────────────────┬──────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│                      Orchestrator                       │
└───┬──────────────┬──────────────┬──────────────┬────────┘
    ▼              ▼              ▼               ▼
 Stage 1        Stage TI       Stage 2         Stage 3
 Rule Engine    TI Lookup      LLM Analysis    Report Gen
 (21 rules)    (QAX TI API)   (LLM API)       (JSON + MD)
```

- **Stage 1** — Fast regex-based filtering with 21 rules (90+ patterns). Classifies skills as `CLEAN` or `SUSPICIOUS`. Supports both English and Chinese patterns.
- **Stage TI** — Threat Intelligence lookup via QAX TI API. IOC extraction is scoped to the source line of network/encoding-related Stage 1 findings (PI-004/005/006/009/011/016). Malicious IOCs escalate verdict; known-benign IOCs can de-escalate severity of individual findings.
- **Stage 2** — Semantic analysis via OpenAI-compatible LLM API for `SUSPICIOUS` skills. Async batched requests with retry logic. Detects 17 threat categories.
- **Stage 3** — Generates per-skill threat reports (QAX ScanReport schema v2.0) and batch summary reports in JSON and Markdown.

### Verdict Logic

The pipeline computes `final_verdict` in order, each stage able to escalate or de-escalate:

**Stage 1 → initial verdict** (findings-based):

| Condition | Result | Action |
|-----------|--------|--------|
| CRITICAL findings ≥ 1 | SUSPICIOUS | REVIEW |
| HIGH findings ≥ 1 | SUSPICIOUS | REVIEW |
| MEDIUM findings ≥ 2 | SUSPICIOUS | REVIEW |
| No findings | CLEAN | ALLOW |

**Stage TI → may escalate or de-escalate**:

| TI Result | Effect |
|-----------|--------|
| Any IOC is `black` (malicious) | Escalate to MALICIOUS |
| Any IOC is `suspicious` | Escalate to SUSPICIOUS if currently CLEAN |
| All related IOCs are `white` (benign) | De-escalate finding severity to LOW |
| All related IOCs are `unknown` | De-escalate CRITICAL → MEDIUM, HIGH → LOW |
| Any `black`/`suspicious` IOC present | No de-escalation for that finding |

**Stage 2 → final verdict** (when LLM is enabled):

| Stage 2 Verdict | Stage 1 CRITICAL findings | Final Result | Action |
|----------------|--------------------------|-------------|--------|
| MALICIOUS | any | MALICIOUS | BLOCK |
| SUSPICIOUS | any | SUSPICIOUS | REVIEW |
| CLEAN | 0 | CLEAN | ALLOW (Stage 1 findings treated as false positives) |
| CLEAN | ≥ 1 | SUSPICIOUS | REVIEW (LLM may have missed a high-confidence threat) |

### False Positive Mitigation

- Code blocks and blockquotes are masked during Stage 1 rule matching
- Educational / defensive skills referencing attack patterns are not flagged
- Stage TI de-escalates findings whose IOCs are known-benign (`white`) or unrecorded (`unknown`)
- Stage 2 LLM overrides Stage 1 false positives when it determines a skill is benign (for non-CRITICAL findings)
- When Stage 2 says CLEAN but Stage 1 has ≥1 CRITICAL finding, result is downgraded to SUSPICIOUS/REVIEW as a safety guard
- Low-confidence LLM results are routed to human review instead of auto-classified

## Installation

```bash
conda activate skills-threat
pip install -e .
```

## Usage

### As CLI

```bash
# Default: Stage 1 on all skills; Stage 2 (LLM) only for skills where Stage 1 is not CLEAN
python -m scanner.cli --path ./skills/ --output ./report/

# Stage 1 + LLM on every skill (previous default behavior; requires API key up front)
python -m scanner.cli --path ./skills/ --stage full-llm

# Stage 1 only (fast, no LLM cost)
python -m scanner.cli --path ./skills/ --stage 1

# Stage 2 only (LLM analysis for all skills; skips Stage 1 rule engine)
python -m scanner.cli --path ./skills/ --stage 2

# Custom LLM model and API endpoint
python -m scanner.cli --path ./skills/ --model glm-4-plus --api-base https://ark.cn-beijing.volces.com/api/v3

# Custom concurrency and batch size
python -m scanner.cli --path ./skills/ --concurrency 5 --batch-size 10

# Resume an interrupted scan
python -m scanner.cli --resume scan-20260310-143000-abc123

# Output per-skill report for every skill (threats → threats/, clean → clean/)
python -m scanner.cli --path ./skills/ --report-all-skills

# Verbose debug logging
python -m scanner.cli --path ./skills/ -v
```

### As Claude Code Skill

```
/scan-skills --path ./skills/
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--path` | `./skills` | Directory containing skill files |
| `--output` | `./report` | Report output directory |
| `--stage` | `full` | `1` (rules only), `2` (LLM only), `full` (rules then LLM only if not CLEAN), `full-llm` (rules then LLM for every skill) |
| `--severity` | `all` | Minimum severity: `critical`, `high`, `medium`, `all` |
| `--format` | `both` | Output format: `json`, `md`, `both` |
| `--batch-size` | `5` | Skills per LLM batch in Stage 2 |
| `--concurrency` | `3` | Concurrent LLM requests |
| `--resume` | — | Resume a scan by its scan ID |
| `--model` | `glm-4-plus` | LLM model name for Stage 2 |
| `--api-base` | Volcano Engine ARK | OpenAI-compatible API base URL |
| `--api-key-env` | `ARK_API_KEY` | Environment variable name for Stage 2 API key |
| `--enable-qax-ti` | off | Enable Stage TI (QAX Threat Intelligence lookup) |
| `--ti-api-key-env` | `QAX_TI_API_KEY` | Environment variable name for QAX TI API key |
| `--log-level` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--verbose` / `-v` | — | Shorthand for `--log-level DEBUG` |
| `--report-all-skills` | — | Output per-skill report for every skill: skills with findings → `threats/`, clean skills → `clean/` (default: only skills with findings get `threats/<id>.json`) |

**`--stage` behavior change:** Older releases treated `full` as “run LLM on every skill.” The default `full` now runs Stage 2 only when Stage 1 is not `CLEAN`. To restore the old behavior, use `--stage full-llm` (or set `scan.stage: full-llm` in the worker config).

## Output

Scan results are written to the output directory:

```
report/
├── summary.json        # Machine-readable scan summary (with skill lists)
├── summary.md          # Human-readable report with tables
├── checkpoint.json     # Resume checkpoint (during scan)
├── threats/            # Per-skill reports for skills with findings (QAX ScanReport schema)
│   ├── {skill-name}-{hash}.json
│   └── ...
└── clean/              # Only when --report-all-skills: per-skill reports for skills with no findings
    ├── {skill-name}-{hash}.json
    └── ...
```

By default, only skills that have stage1/stage2 findings or a non-clean verdict get a per-skill JSON file under `threats/`. With `--report-all-skills`, every skill gets a report: those with findings go to `threats/`, those with no findings go to `clean/`.

### Summary Report

`summary.json` includes counts and specific skill file paths for each verdict:

```json
{
  "results": {
    "clean": 21,
    "suspicious": 3,
    "suspicious_skills": ["skills/foo/foo.zip", "..."],
    "malicious": 2,
    "malicious_skills": ["skills/bar/bar.zip", "..."]
  },
  "top_threat_types": [
    {"type": "social_engineering", "count": 5, "skills": ["..."]}
  ]
}
```

## Worker Mode (RabbitMQ + MongoDB)

In addition to the CLI batch mode, the scanner ships two lightweight local commands for scanning skills directly from ZIP files on disk — no RabbitMQ or MongoDB required.

### Local Batch Scan

#### Single-ZIP scan (`scan-worker-zip`)

Scan one ZIP file and print a QAX-format JSON report to stdout. Useful for quick debugging.

```bash
# Stage 1 only (rules, no LLM)
scan-worker-zip --zip ./skills/foo.zip --config config.yaml

# Stage 1 + Stage 2 LLM (reads scan.* settings from config.yaml)
scan-worker-zip --zip ./skills/foo.zip --config config.yaml --enable-llm
```

#### Batch scan (`scan-worker-batch`)

Recursively scan **all ZIP files** under a directory and write structured reports to an output directory.  Stage 1 runs on every ZIP first; Stage 2 LLM is batched across all skills using `scan.batch_size` and `scan.concurrency` from `config.yaml` (same logic as `scan-skills`).

```bash
# Stage 1 only
scan-worker-batch --path ./skills-store/ --output ./batch-report/ --config config.yaml

# Stage 1 + Stage 2 LLM
scan-worker-batch --path ./skills-store/ --output ./batch-report/ --config config.yaml --enable-llm

# Change log verbosity
scan-worker-batch --path ./skills-store/ --output ./batch-report/ --log-level DEBUG
```

#### Parameters

| Option | Command | Default | Description |
|--------|---------|---------|-------------|
| `--config` | both | `config.yaml` | Worker config YAML; reads `scan.*` section for stage, model, api_key, api_base, batch_size, concurrency |
| `--zip` | `scan-worker-zip` | — | Path to a single ZIP file |
| `--path` | `scan-worker-batch` | — | Directory to search recursively for `.zip` files |
| `--output` | `scan-worker-batch` | — | Output directory for reports |
| `--enable-llm` | both | off | Enable Stage 2 LLM analysis |
| `--log-level` | both | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

#### Batch scan output

```
<output>/
├── summary.json        # Machine-readable scan summary
├── summary.md          # Human-readable summary with tables
└── reports/
    ├── {skill-id}.json # Per-skill QAX report (all skills, regardless of verdict)
    └── ...
```

`skill_path` in every report is the ZIP file's absolute path with the home directory prefix stripped (e.g. `skills-store/author/foo.zip`).

---

### RabbitMQ Worker Architecture

```
RabbitMQ Queue ──► Consumer (main thread: IO + heartbeat)
                       │
                       ▼
                   Worker thread ──► Download skill ZIP
                                     ──► Stage 1 (rules)
                                     ──► Stage 2 (LLM, if needed)
                                     ──► Build QAX report
                                     ──► Write report to MongoDB
                                     ──► ACK message
```

### Install Worker Dependencies

```bash
poetry install --extras worker
```

### Configuration

Copy the example config and edit it:

```bash
cp config.yaml.example config.yaml
```

Key sections in `config.yaml`:

| Section | Field | Description |
|---------|-------|-------------|
| `rabbitmq` | `host`, `port`, `username`, `password` | RabbitMQ connection |
| `rabbitmq` | `queue_name` | Queue to consume from |
| `rabbitmq` | `prefetch_count` | Messages per worker (default: 1) |
| `rabbitmq` | `heartbeat` | Heartbeat interval in seconds (default: 600) |
| `rabbitmq` | `max_retries` | Max retry attempts before marking failed (default: 3) |
| `mongodb` | `uri` | MongoDB connection string (supports replica sets) |
| `mongodb` | `database` | Database name |
| `mongodb` | `tasks_collection` | Collection for task status tracking |
| `mongodb` | `reports_collection` | Collection for scan reports |
| `scan` | `stage` | `full` (conditional LLM), `full-llm` (LLM on every skill), `1`, or `2` |
| `scan` | `model`, `api_base`, `api_key_env` | LLM settings for Stage 2 |
| `scan` | `enable_qax_ti`, `ti_api_key` | Enable Stage TI and provide QAX TI API key |

### Start a Worker

```bash
# Single worker (default)
scan-worker --config config.yaml

# Multiple workers — built-in supervisor auto-restarts crashed processes
scan-worker --config config.yaml --workers 4

# Debug logging
scan-worker --config config.yaml -w 4 -v

# Equivalent module invocation
python -m scanner.worker.cli --config config.yaml --workers 4
```

With `--workers N` (N > 1), a **supervisor process** manages N child worker processes:
- Each child independently connects to RabbitMQ and consumes tasks
- If a child crashes, the supervisor automatically restarts it
- `SIGTERM` / `Ctrl+C` is forwarded to all children for graceful shutdown
- The supervisor waits for all children to finish their current tasks before exiting

### Scaling Across Machines

Workers on different machines can share the same queue — RabbitMQ handles load balancing automatically:

```bash
# Machine A
scan-worker --config config.yaml -w 4

# Machine B
scan-worker --config config.yaml -w 4
```

### Graceful Shutdown and Restart

**Graceful stop** — send `SIGTERM` or `SIGINT` (Ctrl+C):

```bash
# Single worker or supervisor — both handle signals correctly
kill -SIGTERM <pid>
```

The shutdown sequence:
1. Supervisor forwards `SIGTERM` to all child workers
2. Each worker stops accepting new messages
3. Each worker finishes the task currently being processed
4. Each worker ACKs the completed message and exits
5. Supervisor waits up to 30s per child, then force-kills any that hang

**No task loss on restart** — the worker uses manual ACK. If a worker is killed or crashes mid-task:
- The unacknowledged message is automatically re-delivered by RabbitMQ
- MongoDB writes use `upsert`, so re-processing is idempotent
- Task status in the `tasks` collection is updated throughout the lifecycle

| Worker state when stopped | What happens |
|--------------------------|--------------|
| Downloading skill | Message re-delivered, scan restarts |
| Running Stage 1 / Stage 2 | Message re-delivered, scan restarts |
| Report written, before ACK | Message re-delivered, upsert overwrites (idempotent) |
| After ACK | Task fully complete, nothing to redo |

### Fault Recovery

- **Transient failures** (download timeout, network error) are retried up to `max_retries` times
- **Permanent failures** are recorded in MongoDB with `status: "failed"` and an error message
- Query failed tasks: `db.tasks.find({status: "failed"})`

### Message Format

Tasks are submitted as JSON messages to the RabbitMQ queue:

```json
{
  "task_id": "hex_uuid",
  "skill_download_url": "https://...",
  "scan_options": {
    "policy": "balanced",
    "enable_llm": true
  },
  "priority": 5,
  "enqueue_time": "2025-01-01T00:00:00+00:00"
}
```

See `script/send_test_message.py` for a working example that uploads a skill to S3 and submits a scan task.

### Production Deployment

`deploy/` 目录提供了 supervisord 和 systemd 两种部署方案，以及一键更新脚本。

#### Option A: Supervisord (推荐，无需 root)

```bash
# 安装 supervisor（如果没有）
pip install supervisor

# 启动（前台，Ctrl+C 停止）
supervisord -c deploy/supervisord.conf -n

# 或后台启动
supervisord -c deploy/supervisord.conf

# 管理命令
supervisorctl -c deploy/supervisord.conf status          # 查看状态
supervisorctl -c deploy/supervisord.conf restart scan-worker  # 重启
supervisorctl -c deploy/supervisord.conf stop scan-worker     # 停止
supervisorctl -c deploy/supervisord.conf tail -f scan-worker  # 查看日志
```

#### Option B: systemd (需要 root)

```bash
sudo cp deploy/scan-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable scan-worker   # 开机自启
sudo systemctl start scan-worker

# 管理命令
sudo systemctl status scan-worker   # 查看状态
sudo systemctl restart scan-worker  # 重启
sudo journalctl -u scan-worker -f   # 查看日志
```

#### One-click Update

拉取最新代码、安装依赖、重启 worker，一条命令完成：

```bash
bash deploy/update.sh              # supervisord 模式
bash deploy/update.sh systemd      # systemd 模式
```

两种方案的特点对比：

| Feature | supervisord | systemd |
|---------|------------|---------|
| 需要 root | 否 | 是 |
| 开机自启 | 需额外配置 | `systemctl enable` |
| 日志 | 自动轮转 (50MB x 10) | journald |
| 崩溃自动重启 | `autorestart=true` | `Restart=always` |
| 优雅停止超时 | `stopwaitsecs=60` | `TimeoutStopSec=60` |

## Project Structure

```
src/scanner/
├── cli.py              # CLI entry point
├── orchestrator.py     # 4-stage pipeline coordinator
├── loader.py           # Skill directory / ZIP loader
├── models.py           # Data models (Verdict, ThreatCategory, RuleMatch, etc.)
├── verdict_merge.py    # TI de-escalation and verdict reclassification
├── excluded_dirs.py    # Directory exclusion rules for file traversal
├── stage1/
│   ├── engine.py       # Regex rule engine
│   ├── rules.yaml      # Detection rules (PI-001 ~ PI-021)
│   └── advanced.py     # Advanced detection helpers (PA-001, etc.)
├── stage_ti/
│   ├── analyzer.py     # IOC extraction (line-window scoped), TI verdict aggregation
│   └── ti_client.py    # QAX TI API client
├── ioc/
│   └── extractor.py    # IP / domain / URL / Base64-decoded IOC extraction
├── stage2/
│   ├── analyzer.py     # Async LLM semantic analyzer
│   └── prompt_template.md
├── stage3/
│   └── reporter.py     # JSON + Markdown report generator (QAX ScanReport schema v2.0)
└── worker/
    ├── cli.py          # Worker CLI entry point (scan-worker, RabbitMQ mode)
    ├── local_cli.py    # Local CLI entry points (scan-worker-zip / scan-worker-batch)
    ├── config.py       # YAML config loader
    ├── consumer.py     # RabbitMQ consumer (dual-thread architecture)
    ├── task_runner.py  # Single-task scan pipeline
    ├── mongo_store.py  # MongoDB task + report storage
    └── downloader.py   # HTTP download + ZIP extraction
```

## Development

```bash
# Run tests (exclude worker integration tests that require pika/MongoDB)
pytest tests/ --ignore=tests/test_worker.py -v

# Run tests with coverage
pytest tests/ --ignore=tests/test_worker.py -v --cov=scanner
```

## License

MIT
