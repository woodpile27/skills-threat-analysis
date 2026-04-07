"""Shared pipeline policy helpers."""

from __future__ import annotations

from scanner.models import ScanResult, Verdict


def should_run_stage2_in_full_mode(result: ScanResult) -> bool:
    """Return True when a skill should enter Stage 2 in ``full`` mode."""
    if result.stage1 and result.stage1.matched_rules:
        return True
    return bool(result.stage_ti and result.stage_ti.verdict != Verdict.CLEAN)
