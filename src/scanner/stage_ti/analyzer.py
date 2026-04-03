"""Stage TI: Threat Intelligence lookup for IOC entities extracted from skills."""

from __future__ import annotations

import logging
import time
from typing import Any

from scanner.ioc.extractor import extract_entities_from_files, extract_entities
from scanner.models import (
    AnalyzerStatus,
    SkillFile,
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

    def analyze(self, skill: SkillFile) -> StageTIResult:
        """Run TI lookup on a single skill. Never raises."""
        t0 = time.monotonic()
        try:
            return self._do_analyze(skill, t0)
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

    def _do_analyze(self, skill: SkillFile, t0: float) -> StageTIResult:
        # 1. Extract entities
        raw_entities = extract_entities_from_files(skill.files, skill.content)

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
