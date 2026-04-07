"""Local CLI to run a worker-style scan on a single ZIP or a directory of ZIPs."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import tempfile
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from scanner.models import AnalyzerStatus, ScanResult, Verdict
from scanner.pipeline_policy import should_run_stage2_in_full_mode
from scanner.stage1.engine import RuleEngine
from scanner.stage2.analyzer import SemanticAnalyzer
from scanner.stage3.reporter import Reporter
from scanner.verdict_merge import apply_ti_deescalation
from scanner.worker.config import ScanConfig, load_config
from scanner.worker.downloader import _load_from_zip

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_home(path: Path | str) -> str:
    """Return *path* as a POSIX string with the home directory prefix removed.

    E.g. /home/alice/skills/foo.zip  →  skills/foo.zip
    Paths outside $HOME are returned unchanged (as absolute POSIX strings).
    """
    try:
        return Path(path).relative_to(Path.home()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def _merge_verdict(result: ScanResult, s2) -> Verdict:
    """Merge Stage 1 and Stage 2 verdicts (mirrors TaskRunner logic)."""
    if s2.status == AnalyzerStatus.FAILED:
        return result.stage1.verdict if result.stage1 else Verdict.SUSPICIOUS
    if s2.verdict == Verdict.MALICIOUS:
        return Verdict.MALICIOUS
    if s2.verdict == Verdict.SUSPICIOUS:
        return Verdict.SUSPICIOUS
    if s2.verdict == Verdict.CLEAN and s2.confidence >= 0.7:
        return Verdict.CLEAN
    return Verdict.SUSPICIOUS


# ---------------------------------------------------------------------------
# Stage 1 loading (shared between single-ZIP and batch modes)
# ---------------------------------------------------------------------------

def _load_and_stage1(skill_zip: Path, rule_engine: RuleEngine) -> ScanResult:
    """Load *skill_zip* and run Stage 1.  Returns a ScanResult with stage1 set.

    skill.file_path is set to the ZIP's path with $HOME stripped;
    skill.skill_dir is cleared so that reporters use file_path for skill_path.
    """
    with tempfile.TemporaryDirectory() as tmp_root:
        tmp = Path(tmp_root)
        archive_path = tmp / "skill_archive"
        shutil.copy2(skill_zip, archive_path)
        skill = _load_from_zip(archive_path, skill_zip.as_posix())

    # Fix skill_path: use original ZIP path with home directory stripped.
    skill.file_path = _strip_home(skill_zip)
    skill.skill_dir = ""

    stage1 = (
        rule_engine.scan_files(skill.files)
        if skill.files
        else rule_engine.scan(skill.content)
    )
    return ScanResult(
        skill=skill,
        stage1=stage1,
        final_verdict=stage1.verdict,
    )


# ---------------------------------------------------------------------------
# Single-ZIP full pipeline (existing behaviour, now calls _load_and_stage1)
# ---------------------------------------------------------------------------

def _run_stage_ti_single(result: ScanResult, scan_cfg: ScanConfig) -> None:
    """Run Stage TI on a single ScanResult (in-place). Never raises."""
    if not (scan_cfg.enable_qax_ti and scan_cfg.ti_api_key):
        return
    try:
        from scanner.stage_ti.analyzer import TIAnalyzer
        ti = TIAnalyzer(api_key=scan_cfg.ti_api_key)
        try:
            result.stage_ti = ti.analyze(result.skill, result.stage1)
        finally:
            ti.close()
        if result.stage_ti.verdict == Verdict.MALICIOUS:
            result.final_verdict = Verdict.MALICIOUS
        elif (
            result.stage_ti.verdict == Verdict.SUSPICIOUS
            and result.final_verdict == Verdict.CLEAN
        ):
            result.final_verdict = Verdict.SUSPICIOUS
        else:
            new_verdict = apply_ti_deescalation(result.stage1, result.stage_ti)
            if new_verdict is not None:
                result.final_verdict = new_verdict
    except Exception:
        logger.warning("Stage TI failed, continuing", exc_info=True)


def _scan_single_skill(skill_zip: Path, scan_cfg: ScanConfig, enable_llm: bool) -> ScanResult:
    """Run Stage 1 (+ optional Stage TI + optional Stage 2) on a single skill loaded from a local ZIP."""
    rule_engine = RuleEngine()
    result = _load_and_stage1(skill_zip, rule_engine)

    # Stage TI
    _run_stage_ti_single(result, scan_cfg)

    st = scan_cfg.stage
    if st == "1":
        want_stage2 = False
    elif st in ("full-llm", "2"):
        want_stage2 = True
    elif st == "full":
        want_stage2 = should_run_stage2_in_full_mode(result)
    else:
        want_stage2 = False

    if not (enable_llm and want_stage2):
        return result

    api_key = scan_cfg.api_key or os.environ.get(scan_cfg.api_key_env)
    if not api_key:
        logger.warning(
            "Stage 2 skipped: set scan.api_key in config or export %s",
            scan_cfg.api_key_env,
        )
        return result

    analyzer = SemanticAnalyzer(
        model=scan_cfg.model,
        api_key=api_key,
        api_base=scan_cfg.api_base,
        concurrency=scan_cfg.concurrency,
        batch_size=scan_cfg.batch_size,
    )
    skill = result.skill
    ti_entities = result.stage_ti.entities if result.stage_ti else []
    s2 = asyncio.run(analyzer.analyze_batch([(skill.id, skill.content, result.stage1.matched_rules, ti_entities)]))[0]
    result.stage2 = s2
    result.final_verdict = _merge_verdict(result, s2)
    return result


# ---------------------------------------------------------------------------
# Batch Stage 2 (mirrors orchestrator._run_stage2)
# ---------------------------------------------------------------------------

async def _run_stage2_batch(
    results: list[ScanResult],
    scan_cfg: ScanConfig,
    *,
    on_batch_complete: "Callable[[list[ScanResult], list[ScanResult]], None] | None" = None,
) -> None:
    """Run Stage 2 LLM analysis in-place on *results* that need it.

    Batching and concurrency follow the same logic as orchestrator._run_stage2:
    skills are grouped by scan_cfg.batch_size and submitted with scan_cfg.concurrency
    concurrent requests via SemanticAnalyzer.

    *on_batch_complete(batch, all_results)* is called after each batch with:
    - *batch*: only the skills that just finished Stage 2 in this batch
    - *all_results*: the full results list (for summary updates)
    """
    api_key = scan_cfg.api_key or os.environ.get(scan_cfg.api_key_env)

    st = scan_cfg.stage
    if st == "1":
        return
    elif st == "full":
        to_analyze = [
            r for r in results
            if should_run_stage2_in_full_mode(r)
        ]
    else:  # "full-llm" or "2"
        to_analyze = results

    if not to_analyze:
        logger.info("Stage 2: no skills require LLM analysis")
        return

    logger.info("Stage 2: analyzing %d skills with LLM", len(to_analyze))

    analyzer = SemanticAnalyzer(
        model=scan_cfg.model,
        api_key=api_key,
        api_base=scan_cfg.api_base,
        concurrency=scan_cfg.concurrency,
        batch_size=scan_cfg.batch_size,
    )

    for batch_start in range(0, len(to_analyze), scan_cfg.batch_size):
        batch = to_analyze[batch_start:batch_start + scan_cfg.batch_size]
        items = [
            (r.skill.id, r.skill.content,
             r.stage1.matched_rules if r.stage1 else [],
             r.stage_ti.entities if r.stage_ti else [])
            for r in batch
        ]
        stage2_results = await analyzer.analyze_batch(items)

        for r, s2 in zip(batch, stage2_results):
            r.stage2 = s2
            r.final_verdict = _merge_verdict(r, s2)

        completed = batch_start + len(batch)
        logger.info("Stage 2 progress: %d/%d", completed, len(to_analyze))

        if on_batch_complete:
            on_batch_complete(list(batch), results)


# ---------------------------------------------------------------------------
# Batch scan driver
# ---------------------------------------------------------------------------

def _scan_all_zips(
    zip_files: list[Path],
    scan_cfg: ScanConfig,
    enable_llm: bool,
    *,
    on_batch_complete: "Callable[[list[ScanResult], list[ScanResult]], None] | None" = None,
) -> list[ScanResult]:
    """Stage 1 all ZIPs, then batch Stage 2 if LLM is enabled.

    Write sequence (mirrors orchestrator behaviour):
    1. After Stage 1: immediately write reports for skills that will NOT enter
       Stage 2 (CLEAN skills in ``full`` mode, or all skills when Stage 2 is
       disabled / no API key).
    2. After each Stage 2 batch: write only the reports for the skills in that
       batch and refresh summary.json / summary.md.

    *on_batch_complete(batch, all_results)* is called with the newly-finished
    skills and the full results list so callers can write incrementally.
    """
    rule_engine = RuleEngine()
    results: list[ScanResult] = []

    logger.info("Stage 1: scanning %d ZIP files", len(zip_files))
    for zf in zip_files:
        try:
            result = _load_and_stage1(zf, rule_engine)
            results.append(result)
        except Exception:
            logger.exception("Failed to scan %s", zf)

    logger.info(
        "Stage 1 complete: %d total, %d clean, %d not-clean",
        len(results),
        sum(1 for r in results if r.stage1 and r.stage1.verdict == Verdict.CLEAN),
        sum(1 for r in results if r.stage1 and r.stage1.verdict != Verdict.CLEAN),
    )

    # Stage TI — threat intelligence enrichment
    if scan_cfg.enable_qax_ti and scan_cfg.ti_api_key:
        logger.info("Stage TI: enriching %d skills with TI lookups", len(results))
        for r in results:
            _run_stage_ti_single(r, scan_cfg)
        logger.info("Stage TI complete")

    # Determine which skills will NOT enter Stage 2 so we can write them now.
    will_run_s2 = enable_llm and scan_cfg.stage != "1"
    api_key = (scan_cfg.api_key or os.environ.get(scan_cfg.api_key_env)) if will_run_s2 else None

    if will_run_s2 and api_key:
        if scan_cfg.stage in ("full-llm", "2"):
            stage1_only: list[ScanResult] = []
        else:  # "full": only no-finding / TI-clean skills skip Stage 2
            stage1_only = [
                r for r in results
                if not should_run_stage2_in_full_mode(r)
            ]
    else:
        # Stage 2 won't run at all — every skill stays at Stage 1.
        stage1_only = list(results)

    # Write Stage-1-only results immediately after Stage 1 finishes.
    if stage1_only and on_batch_complete:
        logger.info(
            "Writing %d Stage-1-only report(s) (not entering Stage 2)", len(stage1_only)
        )
        on_batch_complete(stage1_only, results)

    if will_run_s2:
        if api_key:
            asyncio.run(
                _run_stage2_batch(results, scan_cfg, on_batch_complete=on_batch_complete)
            )
        else:
            logger.warning(
                "Stage 2 skipped: set scan.api_key in config or export %s",
                scan_cfg.api_key_env,
            )

    return results


# ---------------------------------------------------------------------------
# Single-ZIP CLI  (scan-worker-zip)
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scan-worker-zip",
        description="Run a worker-style scan on a single ZIP and print the JSON report.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to the worker config YAML file (default: config.yaml)",
    )
    parser.add_argument(
        "--zip",
        required=True,
        type=Path,
        help="Path to the local ZIP file to scan.",
    )
    parser.add_argument(
        "--enable-llm",
        action="store_true",
        help="Enable Stage 2 LLM semantic analysis (uses scan.* config).",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.zip.exists():
        logger.error("ZIP file not found: %s", args.zip)
        raise SystemExit(1)

    cfg = load_config(args.config)

    scan_result = _scan_single_skill(args.zip, cfg.scan, enable_llm=args.enable_llm)

    scan_id = (
        f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        f"-{uuid.uuid4().hex[:6]}"
    )
    reporter = Reporter(tempfile.mkdtemp(prefix="worker_local_report_"))
    report = reporter.build_skill_report(scan_result, scan_id)

    print(json.dumps(report, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------------------
# Batch CLI  (scan-worker-batch)
# ---------------------------------------------------------------------------

def parse_args_batch(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scan-worker-batch",
        description=(
            "Recursively scan all ZIP files under --path using worker-style scanning "
            "and write summary + per-skill reports to --output."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to the worker config YAML file (default: config.yaml)",
    )
    parser.add_argument(
        "--path",
        required=True,
        type=Path,
        help="Directory to search recursively for .zip skill files.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory for summary.json, summary.md, and reports/.",
    )
    parser.add_argument(
        "--enable-llm",
        action="store_true",
        help="Enable Stage 2 LLM semantic analysis (uses scan.* config).",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    return parser.parse_args(argv)


def main_batch(argv: list[str] | None = None) -> None:
    args = parse_args_batch(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)

    scan_path: Path = args.path
    if not scan_path.is_dir():
        logger.error("--path is not a directory: %s", scan_path)
        raise SystemExit(1)

    zip_files = sorted(scan_path.rglob("*.zip"))
    if not zip_files:
        logger.warning("No ZIP files found under %s", scan_path)
        raise SystemExit(0)

    logger.info("Found %d ZIP files under %s", len(zip_files), scan_path)

    cfg = load_config(args.config)

    output_dir: Path = args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = output_dir / "reports"

    scan_id = (
        f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        f"-{uuid.uuid4().hex[:6]}"
    )

    reporter = Reporter(output_dir)

    def on_batch_complete(batch: list[ScanResult], all_results: list[ScanResult]) -> None:
        reporter.write_batch(scan_id, batch, all_results, reports_dir)

    results = _scan_all_zips(
        zip_files, cfg.scan, enable_llm=args.enable_llm, on_batch_complete=on_batch_complete
    )

    # Derive final counts for logging.
    total = len(results)
    clean = sum(1 for r in results if r.final_verdict == Verdict.CLEAN)
    suspicious = sum(1 for r in results if r.final_verdict == Verdict.SUSPICIOUS)
    malicious = sum(1 for r in results if r.final_verdict == Verdict.MALICIOUS)

    logger.info(
        "Batch scan complete [%s]: total=%d clean=%d suspicious=%d malicious=%d. "
        "Reports at %s",
        scan_id,
        total,
        clean,
        suspicious,
        malicious,
        output_dir,
    )


def _main_dispatch(argv: list[str] | None = None) -> None:
    """Unified entry point: dispatch to main_batch if --path is given, else main."""
    import sys
    args = argv if argv is not None else sys.argv[1:]
    # If any positional or keyword argument looks like --path, use batch mode.
    if "--path" in args:
        main_batch(argv)
    else:
        main(argv)


if __name__ == "__main__":
    _main_dispatch()
