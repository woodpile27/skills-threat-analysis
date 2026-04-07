"""Single-task scanning pipeline for the worker mode."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any

from scanner.models import AnalyzerStatus, ScanResult, Verdict
from scanner.pipeline_policy import should_run_stage2_in_full_mode
from scanner.stage1.engine import RuleEngine
from scanner.stage2.analyzer import SemanticAnalyzer
from scanner.stage3.reporter import Reporter
from scanner.verdict_merge import apply_ti_deescalation
from scanner.worker.config import ScanConfig
from scanner.worker.downloader import download_and_load
from scanner.worker.mongo_store import MongoStore

logger = logging.getLogger(__name__)


class TaskRunner:
    """Execute a single scan task: download -> stage1 -> stage2 -> report."""

    def __init__(self, scan_config: ScanConfig, mongo: MongoStore):
        self._config = scan_config
        self._mongo = mongo
        self._rule_engine = RuleEngine()
        self._reporter = Reporter(tempfile.mkdtemp(prefix="worker_report_"))

    def execute(self, task_msg: dict[str, Any]) -> None:
        task_id: str = task_msg["task_id"]
        url: str = task_msg["skill_download_url"]
        scan_options: dict = task_msg.get("scan_options", {})
        enable_llm = scan_options.get("enable_llm", True)
        self._scan_options = {
            "policy": scan_options.get("policy", "balanced"),
            "enable_llm": enable_llm,
            "enable_qax_ti": scan_options.get("enable_qax_ti", True),
            "analyzers": scan_options.get("analyzers", None),
            "disabled_rules": scan_options.get("disabled_rules", []),
            "severity_overrides": scan_options.get("severity_overrides", {}),
            "llm_provider": scan_options.get("llm_provider", ""),
        }
        scan_id = (
            f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
            f"-{uuid.uuid4().hex[:6]}"
        )

        logger.info("Task %s: starting scan %s for %s (policy=%s)",
                     task_id, scan_id, url, self._scan_options["policy"])

        self._mongo.update_task_status(task_id, "processing")

        try:
            skill = download_and_load(url)
            logger.info("Task %s: downloaded skill %s (%d bytes)",
                        task_id, skill.id, skill.size_bytes)

            scan_result = self._scan(skill, enable_llm)

            report = self._reporter.build_skill_report(scan_result, scan_id)
            self._mongo.save_report(task_id, scan_id, report)

            self._mongo.update_task_status(
                task_id, "completed",
                extra={
                    "scan_id": scan_id,
                    "verdict": scan_result.final_verdict.value,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            logger.info("Task %s: completed — verdict=%s",
                        task_id, scan_result.final_verdict.value)

        except Exception:
            logger.exception("Task %s: scan failed", task_id)
            raise

    # ------------------------------------------------------------------ #

    def _scan(self, skill, enable_llm: bool) -> ScanResult:
        """Run Stage 1 (+ optional Stage 2) on a single skill."""
        stage1 = (
            self._rule_engine.scan_files(skill.files)
            if skill.files
            else self._rule_engine.scan(skill.content)
        )
        result = ScanResult(
            skill=skill,
            stage1=stage1,
            final_verdict=stage1.verdict,
        )
        logger.info("Task stage1: verdict=%s, %d rules matched",
                     stage1.verdict.value, len(stage1.matched_rules))

        # Stage TI — threat intelligence enrichment
        if self._scan_options.get("enable_qax_ti") and self._config.ti_api_key:
            try:
                from scanner.stage_ti.analyzer import TIAnalyzer
                ti = TIAnalyzer(api_key=self._config.ti_api_key)
                try:
                    result.stage_ti = ti.analyze(skill, result.stage1)
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
                logger.info("Task stage_ti: verdict=%s, %d entities",
                            result.stage_ti.verdict.value,
                            len(result.stage_ti.entities))
            except Exception:
                logger.warning("Stage TI failed, continuing", exc_info=True)

        st = self._config.stage
        if st == "1":
            want_stage2 = False
        elif st in ("full-llm", "2"):
            want_stage2 = True
        elif st == "full":
            want_stage2 = should_run_stage2_in_full_mode(result)
        else:
            want_stage2 = False

        need_stage2 = enable_llm and want_stage2

        if need_stage2:
            api_key = self._config.api_key or os.environ.get(self._config.api_key_env)
            if not api_key:
                logger.warning(
                    "Stage 2 skipped: set scan.api_key in config or export %s",
                    self._config.api_key_env,
                )
                return result

            analyzer = SemanticAnalyzer(
                model=self._config.model,
                api_key=api_key,
                api_base=self._config.api_base,
                concurrency=self._config.concurrency,
                batch_size=self._config.batch_size,
            )
            ti_entities = result.stage_ti.entities if result.stage_ti else []
            items = [(skill.id, skill.content, stage1.matched_rules, ti_entities)]
            stage2_results = asyncio.run(analyzer.analyze_batch(items))
            s2 = stage2_results[0]
            result.stage2 = s2
            result.final_verdict = self._merge_verdict(result, s2)
            logger.info("Task stage2: verdict=%s, confidence=%.2f",
                         s2.verdict.value, s2.confidence)

        return result

    @staticmethod
    def _merge_verdict(result: ScanResult, s2) -> Verdict:
        """Merge Stage 1 and Stage 2 verdicts (mirrors Orchestrator logic)."""
        if s2.status == AnalyzerStatus.FAILED:
            return result.stage1.verdict if result.stage1 else Verdict.SUSPICIOUS
        if s2.verdict == Verdict.MALICIOUS:
            return Verdict.MALICIOUS
        if s2.verdict == Verdict.SUSPICIOUS:
            return Verdict.SUSPICIOUS
        if s2.verdict == Verdict.CLEAN and s2.confidence >= 0.7:
            return Verdict.CLEAN
        return Verdict.SUSPICIOUS
