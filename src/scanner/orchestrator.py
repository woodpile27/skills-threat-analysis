"""Orchestrator: coordinate the three-stage scanning pipeline."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from scanner.loader import load_skills
from scanner.models import AnalyzerStatus, ScanResult, SkillFile, Verdict
from scanner.stage1.engine import RuleEngine
from scanner.stage2.analyzer import SemanticAnalyzer
from scanner.stage3.reporter import Reporter
from scanner.stage_ti.analyzer import TIAnalyzer
from scanner.pipeline_policy import should_run_stage2_in_full_mode
from scanner.verdict_merge import apply_ti_deescalation

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        skills_dir: str | Path,
        output_dir: str | Path = "./report",
        stage: str = "full",
        severity_filter: str = "all",
        batch_size: int = 5,
        concurrency: int = 3,
        resume_scan_id: str | None = None,
        model: str | None = None,
        api_base: str | None = None,
        api_key_env: str = "ARK_API_KEY",
        report_all_skills: bool = False,
        ti_api_key: str | None = None,
        enable_qax_ti: bool = False,
    ):
        self._skills_dir = Path(skills_dir)
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._stage = stage
        self._severity_filter = severity_filter
        self._batch_size = batch_size
        self._concurrency = concurrency
        self._model = model
        self._api_base = api_base
        self._api_key_env = api_key_env
        self._ti_api_key = ti_api_key
        self._enable_qax_ti = enable_qax_ti
        self._rule_engine = RuleEngine()
        self._reporter = Reporter(self._output_dir, report_all_skills=report_all_skills)

        if resume_scan_id:
            self._scan_id = resume_scan_id
            self._checkpoint = self._load_checkpoint()
        else:
            self._scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
            self._checkpoint: dict | None = None

    def run(self) -> None:
        """Main entry point — runs the full scan pipeline."""
        import os

        logger.info("Starting scan %s on %s", self._scan_id, self._skills_dir)

        # Stage 2 will always run: require API key up front
        if self._stage in ("2", "full-llm"):
            api_key = os.environ.get(self._api_key_env)
            if not api_key:
                logger.error(
                    "%s not set. Stage 2 requires an API key. "
                    "Use --stage 1 to run rules-only scan, or set the environment variable.",
                    self._api_key_env,
                )
                return

        # Handle stage 2-only mode
        if self._stage == "2":
            # Create ScanResult objects with empty stage1 for all skills
            stage1_results = [
                ScanResult(
                    skill=skill,
                    stage1=None,
                    final_verdict=Verdict.SUSPICIOUS  # Force all to be analyzed
                )
                for skill in load_skills(self._skills_dir)
            ]
            results = asyncio.run(self._run_stage2(stage1_results))
        else:
            # Normal flow: stage 1 → stage 2 (if not stage 1 only)
            stage1_results = self._run_stage1()
            logger.info(
                "Stage 1 complete: %d total, %d clean, %d suspicious",
                len(stage1_results),
                sum(1 for r in stage1_results if r.stage1.verdict == Verdict.CLEAN),
                sum(1 for r in stage1_results if r.stage1.verdict ==
                    Verdict.SUSPICIOUS),
            )

            # Stage TI — threat intelligence enrichment
            if self._enable_qax_ti and self._ti_api_key:
                self._run_stage_ti(stage1_results)

            if self._stage == "1":
                # Finalize with stage 1 only
                for r in stage1_results:
                    r.final_verdict = r.stage1.verdict
                self._reporter.generate(self._scan_id, stage1_results)
                logger.info(
                    "Stage-1-only scan complete. Report at %s", self._output_dir)
                return

            if self._stage == "full":
                needs_llm = any(
                    should_run_stage2_in_full_mode(r)
                    for r in stage1_results
                )
                if not needs_llm:
                    logger.info(
                        "Stage 2 skipped: no skills have Stage 1 findings or non-clean TI results. Report at %s",
                        self._output_dir,
                    )
                    results = stage1_results
                    summary = self._reporter.generate(self._scan_id, results)
                    logger.info(
                        "Scan complete. Malicious: %d, Suspicious: %d, Clean: %d. Report at %s",
                        summary.malicious, summary.suspicious, summary.clean, self._output_dir,
                    )
                    return

                api_key = os.environ.get(self._api_key_env)
                if not api_key:
                    logger.error(
                        "%s not set. Stage 2 requires an API key for skills with Stage 1 findings or non-clean TI results. "
                        "Use --stage 1 to run rules-only scan, or set the environment variable.",
                        self._api_key_env,
                    )
                    return

            results = asyncio.run(self._run_stage2(stage1_results))

        # Stage 3 — report
        summary = self._reporter.generate(self._scan_id, results)
        logger.info(
            "Scan complete. Malicious: %d, Suspicious: %d, Clean: %d. Report at %s",
            summary.malicious, summary.suspicious, summary.clean, self._output_dir,
        )

    def _run_stage_ti(self, results: list[ScanResult]) -> None:
        """Enrich ScanResult objects with TI lookups (in-place)."""
        analyzer = TIAnalyzer(api_key=self._ti_api_key)
        try:
            for r in results:
                r.stage_ti = analyzer.analyze(r.skill, r.stage1)
                # Merge TI verdict with Stage 1 verdict
                if r.stage_ti.verdict == Verdict.MALICIOUS:
                    r.final_verdict = Verdict.MALICIOUS
                elif (
                    r.stage_ti.verdict == Verdict.SUSPICIOUS
                    and r.final_verdict == Verdict.CLEAN
                ):
                    r.final_verdict = Verdict.SUSPICIOUS
                else:
                    new_verdict = apply_ti_deescalation(r.stage1, r.stage_ti)
                    if new_verdict is not None:
                        r.final_verdict = new_verdict
        finally:
            analyzer.close()
        logger.info("Stage TI complete: %d skills enriched", len(results))

    def _run_stage1(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        processed = 0

        for skill in load_skills(self._skills_dir):
            # Skip if resuming past checkpoint
            if self._checkpoint and processed < self._checkpoint.get("stage1_completed", 0):
                processed += 1
                continue

            stage1 = (
                self._rule_engine.scan_files(skill.files)
                if skill.files
                else self._rule_engine.scan(skill.content)
            )
            results.append(ScanResult(
                skill=skill,
                stage1=stage1,
                final_verdict=stage1.verdict,
            ))
            processed += 1

            if processed % 10000 == 0:
                logger.info("Stage 1 progress: %d files processed", processed)

        return results

    async def _run_stage2(self, stage1_results: list[ScanResult]) -> list[ScanResult]:
        import os
        analyzer = SemanticAnalyzer(
            model=self._model,
            api_key=os.environ.get(self._api_key_env),
            api_base=self._api_base,
            concurrency=self._concurrency,
            batch_size=self._batch_size,
        )

        if self._stage in ("2", "full-llm"):
            to_analyze = stage1_results
        elif self._stage == "full":
            to_analyze = [
                r for r in stage1_results
                if should_run_stage2_in_full_mode(r)
            ]
        else:
            to_analyze = []

        logger.info("Stage 2: analyzing %d skills with LLM", len(to_analyze))

        # Process in batches
        checkpoint_index = 0
        if self._checkpoint:
            checkpoint_index = self._checkpoint.get("stage2_completed", 0)

        for batch_start in range(checkpoint_index, len(to_analyze), self._batch_size):
            batch = to_analyze[batch_start:batch_start + self._batch_size]
            items = [
                (r.skill.id, r.skill.content,
                 r.stage1.matched_rules if r.stage1 else [],
                 r.stage_ti.entities if r.stage_ti else [])
                for r in batch
            ]
            stage2_results = await analyzer.analyze_batch(items)

            for r, s2 in zip(batch, stage2_results):
                r.stage2 = s2
                # Determine final verdict
                if s2.status == AnalyzerStatus.FAILED:
                    # LLM analysis failed — fall back to stage 1 verdict
                    r.final_verdict = (
                        r.stage1.verdict if r.stage1
                        else Verdict.SUSPICIOUS
                    )
                elif s2.verdict == Verdict.MALICIOUS:
                    r.final_verdict = Verdict.MALICIOUS
                elif s2.verdict == Verdict.SUSPICIOUS:
                    r.final_verdict = Verdict.SUSPICIOUS
                elif s2.verdict == Verdict.CLEAN:
                    if s2.confidence >= 0.7:
                        # LLM confident it's clean → downgrade
                        r.final_verdict = Verdict.CLEAN
                    else:
                        # Low confidence clean → keep suspicious
                        r.final_verdict = Verdict.SUSPICIOUS
                else:
                    r.final_verdict = s2.verdict

            # Save checkpoint and update report incrementally
            self._save_checkpoint(
                stage1_completed=len(stage1_results),
                stage2_completed=batch_start + len(batch),
                stage2_total=len(to_analyze),
            )
            self._reporter.generate(self._scan_id, stage1_results)

            completed = batch_start + len(batch)
            logger.info("Stage 2 progress: %d/%d, report updated", completed, len(to_analyze))

        return stage1_results

    def _save_checkpoint(self, stage1_completed: int, stage2_completed: int, stage2_total: int) -> None:
        cp = {
            "scan_id": self._scan_id,
            "stage1_completed": stage1_completed,
            "stage2_completed": stage2_completed,
            "stage2_remaining": stage2_total - stage2_completed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        path = self._output_dir / "checkpoint.json"
        path.write_text(json.dumps(cp, indent=2), encoding="utf-8")

    def _load_checkpoint(self) -> dict | None:
        path = self._output_dir / "checkpoint.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("scan_id") == self._scan_id:
                logger.info("Resuming scan %s from checkpoint", self._scan_id)
                return data
        return None
