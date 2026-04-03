# Skills Threat Analysis

Prompt Injection scanner for Claude Code skills.

## Project Structure

- `src/scanner/` - Main package
  - `models.py` - Data models (Verdict, Severity, ThreatCategory, RuleMatch, ScanResult, etc.)
  - `loader.py` - File loader that traverses skill directories and ZIP packages
  - `orchestrator.py` - Pipeline coordinator for 4-stage scanning
  - `verdict_merge.py` - TI de-escalation logic and verdict reclassification
  - `excluded_dirs.py` - Directory exclusion rules for file traversal
  - `cli.py` - CLI entry point
  - `stage1/` - Stage 1: Rule-based regex matching
    - `engine.py` - Regex matching engine
    - `rules.yaml` - Detection rule definitions
    - `advanced.py` - Advanced detection helpers
  - `stage_ti/` - Stage TI: Threat Intelligence lookup
    - `analyzer.py` - IOC extraction and TI verdict aggregation
    - `ti_client.py` - QAX TI API client
  - `ioc/` - IOC extraction utilities
    - `extractor.py` - IP/domain/URL/Base64-encoded IOC extraction
  - `stage2/` - Stage 2: LLM semantic analysis
    - `analyzer.py` - Anthropic API-based semantic analysis
    - `prompt_template.md` - Prompt template for LLM analysis
  - `stage3/` - Stage 3: Report generation
    - `reporter.py` - Report generator (JSON + Markdown)
  - `worker/` - Worker mode for batch/queue-driven scanning
    - `local_cli.py` - Local CLI for scanning ZIP packages
    - `task_runner.py` - Single-task scanning pipeline
    - `consumer.py` - RabbitMQ consumer
    - `downloader.py` - Skill package downloader
    - `mongo_store.py` - MongoDB result storage
    - `config.py` - Worker configuration
- `tests/` - Test suite
- `docs/` - Design documentation

## Development

```bash
conda activate skills-threat
pip install -e .
pytest tests/ --ignore=tests/test_worker.py
```

## Running

```bash
# Scan local skill directories
python -m scanner.cli --path ./skills/ --output ./report/

# Scan a single ZIP package (worker mode)
python -m scanner.worker.local_cli --config config.yaml --zip /path/to/skill.zip
```
