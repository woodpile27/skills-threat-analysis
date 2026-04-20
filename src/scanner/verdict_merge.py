"""Verdict merge helpers for TI de-escalation logic."""

from __future__ import annotations

from urllib.parse import urlparse

from scanner.models import (
    Severity,
    Stage1Result,
    StageTIResult,
    Verdict,
)

_SEVERITY_ORDER = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
    Severity.LOW: 2, Severity.INFO: 1, Severity.SAFE: 0,
}


def apply_ti_deescalation(
    stage1: Stage1Result | None,
    stage_ti: StageTIResult,
) -> Verdict | None:
    """Apply per-finding TI de-escalation, modifying severity in-place.

    Returns the re-classified verdict after adjustments, or None if no
    findings were adjusted.

    For each CRITICAL/HIGH finding, collect ALL related TI entities and
    apply de-escalation based on the combined risk:
    - Any black/suspicious entity → no de-escalation
    - Any white entity (no black/suspicious) → CRITICAL→LOW, HIGH→LOW
    - All unknown → CRITICAL→MEDIUM, HIGH→LOW
    """
    if not stage1 or not stage1.matched_rules:
        return None
    if not stage_ti or not stage_ti.entities:
        return None
    # Only de-escalate when TI verdict is CLEAN; MALICIOUS/SUSPICIOUS
    # are handled by the caller's escalation logic.
    if stage_ti.verdict != Verdict.CLEAN:
        return None

    # Build entity→risk mapping (entity value + URL hostname)
    entity_risk: dict[str, str] = {}
    for e in stage_ti.entities:
        entity_risk[e.entity] = e.risk
        if "://" in e.entity:
            try:
                parsed = urlparse(e.entity)
                if parsed.hostname:
                    entity_risk[parsed.hostname] = e.risk
            except Exception:
                pass

    adjusted = False
    for m in stage1.matched_rules:
        if m.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue

        # Collect ALL related entities for this finding
        related: list[tuple[str, str]] = []  # (entity, risk)
        for val, risk in entity_risk.items():
            if val in m.matched_text:
                related.append((val, risk))

        if not related:
            continue

        risks = {r for _, r in related}
        entities_desc = ", ".join(f"{v}({r})" for v, r in related)

        # Any black/suspicious → no de-escalation
        if risks & {"black", "suspicious"}:
            continue

        # Extract base IOCs (hostname from URLs, raw value for domain/IP)
        base_iocs: set[str] = set()
        for val, _risk in related:
            if "://" in val:
                try:
                    parsed = urlparse(val)
                    if parsed.hostname:
                        base_iocs.add(parsed.hostname)
                except Exception:
                    base_iocs.add(val)
            else:
                base_iocs.add(val)

        original = m.severity.value
        has_white = "white" in risks

        if has_white:
            # At least one white (rest unknown) → more aggressive de-escalation
            m.severity = Severity.LOW
            m.ti_note = (
                f"关联 IOC [{entities_desc}] 中存在 TI 确认安全(white)，"
                f"severity 从 {original} 降为 LOW"
            )
            m.ti_ioc = ",".join(sorted(base_iocs))
            adjusted = True
        else:
            # All unknown
            if m.severity == Severity.CRITICAL:
                # PI-024 (remote instruction loading): unknown TI only
                # de-escalates to HIGH — the pattern itself is dangerous
                # regardless of domain reputation (fresh attacker domains
                # are always unknown in TI).
                if m.rule_id == "PI-024":
                    m.severity = Severity.HIGH
                    m.ti_note = (
                        f"关联 IOC [{entities_desc}] 均在 TI 中无记录(unknown)，"
                        f"severity 从 CRITICAL 降为 HIGH"
                    )
                else:
                    m.severity = Severity.MEDIUM
                    m.ti_note = (
                        f"关联 IOC [{entities_desc}] 均在 TI 中无记录(unknown)，"
                        f"severity 从 CRITICAL 降为 MEDIUM"
                    )
                m.ti_ioc = ",".join(sorted(base_iocs))
                adjusted = True
            elif m.severity == Severity.HIGH:
                # PA-004 (hidden URLs in HTML comments): unknown TI only
                # de-escalates to MEDIUM — hidden URLs are suspicious even
                # without TI confirmation (fresh C2 domains are often unknown).
                if m.rule_id == "PA-004":
                    m.severity = Severity.MEDIUM
                    m.ti_note = (
                        f"关联 IOC [{entities_desc}] 均在 TI 中无记录(unknown)，"
                        f"severity 从 HIGH 降为 MEDIUM"
                    )
                else:
                    m.severity = Severity.LOW
                    m.ti_note = (
                        f"关联 IOC [{entities_desc}] 均在 TI 中无记录(unknown)，"
                        f"severity 从 HIGH 降为 LOW"
                    )
                m.ti_ioc = ",".join(sorted(base_iocs))
                adjusted = True

    if not adjusted:
        return None
    return _reclassify(stage1.matched_rules)


def _reclassify(matches: list) -> Verdict:
    """Re-compute verdict from (modified) severities.

    Deduplicates by (rule_id, ti_ioc) — findings from the same rule
    targeting the same base IOC count only once (highest severity wins).
    Findings without ti_ioc (not de-escalated) use their own identity.
    """
    best: dict[tuple, Severity] = {}
    for i, m in enumerate(matches):
        key = (m.rule_id, m.ti_ioc) if m.ti_ioc else (m.rule_id, i)
        prev = best.get(key)
        if prev is None or _SEVERITY_ORDER[m.severity] > _SEVERITY_ORDER[prev]:
            best[key] = m.severity

    critical = sum(1 for s in best.values() if s == Severity.CRITICAL)
    high = sum(1 for s in best.values() if s == Severity.HIGH)
    medium = sum(1 for s in best.values() if s == Severity.MEDIUM)
    if critical >= 1 or high >= 1 or medium >= 2:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN
