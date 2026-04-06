"""Stage TI: Threat Intelligence lookup for IOC entities extracted from skills."""

from __future__ import annotations

import logging
import time
from typing import Any

from scanner.ioc.extractor import extract_entities
from scanner.models import (
    AnalyzerStatus,
    SkillFile,
    Stage1Result,
    StageTIResult,
    TIEntityResult,
    Verdict,
)
from scanner.stage_ti.ti_client import (
    TI_WEBAPI_BASE,
    TI_V2_BASE,
    TiHttpClient,
    compromise_and_judge,
    get_ips_reputation,
)

logger = logging.getLogger(__name__)


# Stage1 rules whose surrounding line is likely to contain real network/encoding IOCs.
# IOCs are only extracted from the source line of findings matching one of these rules.
TI_TARGET_RULES: frozenset[str] = frozenset({
    # -- Network exploitation --
    "PI-004",  # context_exfiltration: send/post ... to https?://
    "PI-006",  # dangerous_operation: curl/wget URLs, base64 droppers, paste-to-shell
    "PI-009",  # network_exfiltration: ngrok URLs, nslookup, dns.resolve
    "PI-016",  # remote_binary_download: URLs to .exe/.sh/.bin
    # -- Suspicious encoding (base64 payloads decoded by IOC extractor) --
    "PI-005",  # steganographic_injection: base64/atob/btoa with injection keywords
    "PI-011",  # obfuscation_standalone: base64.b64decode, fromCharCode, etc.
})


def _line_window(content: str, position: tuple[int, int]) -> tuple[str, int]:
    """Return ``(line_text, line_start_offset)`` for the line containing the match."""
    start, end = position
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end], line_start


def _extract_entities_from_findings(
    stage1: Stage1Result,
    skill: SkillFile,
) -> list[tuple[str, str, str, int, int, str]]:
    """Extract IOCs only from network/encoding-related stage1 findings.

    Scope per finding = the source line containing the match (deduped per
    ``(source_file, line_start)``). Falls back to the finding's ``matched_text``
    if the source file content is unavailable. Returned positions are
    absolute file offsets, suitable for direct use in ``TIEntityResult``.
    """
    if not stage1 or not stage1.matched_rules:
        return []

    file_content = {f.rel_path: f.content for f in skill.files}
    seen_windows: set[tuple] = set()
    seen_entities: set[tuple[str, str]] = set()
    results: list[tuple[str, str, str, int, int, str]] = []

    for m in stage1.matched_rules:
        if m.rule_id not in TI_TARGET_RULES:
            continue

        content = file_content.get(m.source_file)
        if content is None:
            # Fallback: file content unavailable, scan only the matched_text.
            window_text, base_offset = m.matched_text, 0
            window_key = ("__fallback__", m.source_file, m.position[0])
        else:
            window_text, base_offset = _line_window(content, m.position)
            window_key = ("__line__", m.source_file, base_offset)

        if window_key in seen_windows:
            continue
        seen_windows.add(window_key)

        for kind, value, src, start, end, decoded_from in extract_entities(
            window_text, m.source_file
        ):
            key = (kind, value)
            if key in seen_entities:
                continue
            seen_entities.add(key)
            results.append(
                (kind, value, src, base_offset + start, base_offset + end, decoded_from)
            )

    return results


class TIAnalyzer:
    """Extract IOCs from skill content and query QAX TI for reputation."""

    def __init__(self, api_key: str, timeout: int = 30) -> None:
        self._client = TiHttpClient()
        self._client.load_config({
            "endpoint": TI_WEBAPI_BASE,
            "endpointv2": TI_V2_BASE,
            "key": api_key,
        })
        self._timeout = timeout

    def analyze(
        self,
        skill: SkillFile,
        stage1: Stage1Result | None = None,
    ) -> StageTIResult:
        """Run TI lookup on a single skill. Never raises.

        Only extracts IOCs from the source line of stage1 findings whose
        ``rule_id`` is in :data:`TI_TARGET_RULES`. If *stage1* is ``None``
        or has no matching findings, returns CLEAN with no entities.
        """
        t0 = time.monotonic()
        try:
            return self._do_analyze(skill, stage1, t0)
        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            logger.warning("Stage TI failed for %s: %s", skill.id, exc, exc_info=True)
            return StageTIResult(
                verdict=Verdict.CLEAN,
                entities=[],
                duration_ms=duration_ms,
                status=AnalyzerStatus.FAILED,
                error=str(exc),
            )

    def _do_analyze(
        self,
        skill: SkillFile,
        stage1: Stage1Result | None,
        t0: float,
    ) -> StageTIResult:
        # 1. Extract entities — only from network/encoding-related stage1 findings
        raw_entities = (
            _extract_entities_from_findings(stage1, skill) if stage1 else []
        )

        if not raw_entities:
            duration_ms = int((time.monotonic() - t0) * 1000)
            return StageTIResult(
                verdict=Verdict.CLEAN,
                entities=[],
                duration_ms=duration_ms,
            )

        # 2. Split into IPs and domains/URLs
        ips: list[str] = []
        domains_urls: list[str] = []
        # Track source_file, position, and decoded_from per entity for reporting
        entity_meta: dict[str, tuple[str, int, int, str]] = {}  # value -> (source_file, start, end, decoded_from)

        for kind, value, source_file, start, end, decoded_from in raw_entities:
            entity_meta[value] = (source_file, start, end, decoded_from)
            if kind == "ip":
                ips.append(value)
            else:
                domains_urls.append(value)

        logger.debug(
            "Skill %s: extracted %d IPs, %d domains/URLs",
            skill.id, len(ips), len(domains_urls),
        )

        # 3. Query TI
        ip_results: dict[str, Any] = {}
        domain_results: dict[str, Any] = {}

        if ips:
            try:
                ip_results = get_ips_reputation(self._client, ips)
            except Exception as exc:
                logger.warning("TI IP lookup failed: %s", exc)

        if domains_urls:
            try:
                domain_results = compromise_and_judge(self._client, domains_urls)
            except Exception as exc:
                logger.warning("TI domain/URL lookup failed: %s", exc)

        # 4. Build entity results
        entities: list[TIEntityResult] = []

        for ip in ips:
            ti_data = ip_results.get(ip)
            risk = ti_data.get("risk", "unknown") if ti_data else "unknown"
            tags = ti_data.get("tags", []) if ti_data else []
            meta = entity_meta.get(ip, ("", 0, 0, ""))
            entities.append(TIEntityResult(
                entity=ip,
                kind="ip",
                risk=risk,
                tags=tags,
                source_file=meta[0],
                position=(meta[1], meta[2]),
                decoded_from=meta[3],
            ))

        for du in domains_urls:
            ti_data = domain_results.get(du)
            risk = ti_data.get("risk", "unknown") if ti_data else "unknown"
            tags = ti_data.get("tags", []) if ti_data else []
            meta = entity_meta.get(du, ("", 0, 0, ""))
            entities.append(TIEntityResult(
                entity=du,
                kind="domain_or_url",
                risk=risk,
                tags=tags,
                source_file=meta[0],
                position=(meta[1], meta[2]),
                decoded_from=meta[3],
            ))

        # 5. Compute verdict (worst-of)
        verdict = Verdict.CLEAN
        for ent in entities:
            if ent.risk == "black":
                verdict = Verdict.MALICIOUS
                break
            elif ent.risk == "suspicious":
                verdict = Verdict.SUSPICIOUS

        duration_ms = int((time.monotonic() - t0) * 1000)
        return StageTIResult(
            verdict=verdict,
            entities=entities,
            duration_ms=duration_ms,
        )

    def close(self) -> None:
        self._client.close()
