"""Stage 2: LLM-based semantic analysis for prompt injection detection."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from pathlib import Path
from string import Template
from typing import Any
from urllib.parse import urlparse

import openai

from scanner.models import (
    AnalyzerStatus,
    RuleMatch,
    Severity,
    Stage2Result,
    TIEntityResult,
    Threat,
    ThreatCategory,
    Verdict,
)

logger = logging.getLogger(__name__)

# Patterns indicating the LLM refused to answer (content safety filter).
_REFUSAL_PATTERNS = [
    "抱歉", "无法回答", "无法提供", "未找到相关结果",
    "我不能", "不适合回答", "无法处理",
    "i can't", "i cannot", "i'm unable", "i am unable",
    "against my guidelines",
]


class LLMRefusalError(Exception):
    """Raised when the LLM refuses to analyze content."""
    pass


_PROMPT_TEMPLATE_PATH = Path(__file__).parent / "prompt_template.md"
_THREAT_CATEGORY_MAP = {
    "instruction_override": ThreatCategory.PROMPT_INJECTION,
    "role_hijacking": ThreatCategory.PROMPT_INJECTION,
    "context_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "steganographic_injection": ThreatCategory.UNICODE_STEGANOGRAPHY,
    "dangerous_operation": ThreatCategory.COMMAND_INJECTION,
    "social_engineering": ThreatCategory.SOCIAL_ENGINEERING,
    "system_prompt_manipulation": ThreatCategory.PROMPT_INJECTION,
    # New categories from skill-scan-1.0.0 integration
    "prompt_injection": ThreatCategory.PROMPT_INJECTION,
    "command_injection": ThreatCategory.COMMAND_INJECTION,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "hardcoded_secrets": ThreatCategory.HARDCODED_SECRETS,
    "obfuscation": ThreatCategory.OBFUSCATION,
    "privilege_escalation": ThreatCategory.PRIVILEGE_ESCALATION,
    "unicode_steganography": ThreatCategory.UNICODE_STEGANOGRAPHY,
}
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Max content length to send to LLM (chars). Truncate longer skills.
_MAX_CONTENT_LENGTH = 12000
# Max number of matched rules to include in LLM prompt.
_MAX_RULES_IN_PROMPT = 30
# Max CRITICAL matches to show per rule_id (not deduplicated — each reveals different evidence).
_MAX_CRITICAL_PER_RULE = 5

# Default: Volcano Engine ARK API
_DEFAULT_API_BASE = "https://ark.cn-beijing.volces.com/api/v3"
_DEFAULT_MODEL = "glm-4-plus"


class SemanticAnalyzer:
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
        max_retries: int = 3,
        concurrency: int = 3,
        batch_size: int = 5,
    ):
        self._model = model or _DEFAULT_MODEL
        self._client = openai.AsyncOpenAI(
            api_key=api_key or "required-but-set-via-env",
            base_url=api_base or _DEFAULT_API_BASE,
        )
        self._max_retries = max_retries
        self._semaphore = asyncio.Semaphore(concurrency)
        self._batch_size = batch_size
        self._prompt_template = Template(_PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8"))

    async def analyze_batch(
        self, items: list[tuple[str, str, list[RuleMatch], list[TIEntityResult]]]
    ) -> list[Stage2Result]:
        """Analyze a batch of skills concurrently.

        Args:
            items: list of (skill_id, content, matched_rules, ti_entities) tuples.

        Returns:
            list of Stage2Result in the same order.
        """
        tasks = [
            self._analyze_one(skill_id, content, matched_rules, ti_entities)
            for skill_id, content, matched_rules, ti_entities in items
        ]
        return await asyncio.gather(*tasks)

    async def _analyze_one(
        self, skill_id: str, content: str, matched_rules: list[RuleMatch],
        ti_entities: list[TIEntityResult] | None = None,
    ) -> Stage2Result:
        start = time.monotonic()
        async with self._semaphore:
            prompt = self._build_prompt(content, matched_rules, ti_entities or [])
            for attempt in range(1, self._max_retries + 1):
                try:
                    result = await self._call_llm(prompt)
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    parsed = self._parse_response(result, elapsed_ms)
                    threat_summary = ", ".join(t.category.value for t in parsed.threats) if parsed.threats else "none"
                    logger.debug(
                        "Skill %s: verdict=%s confidence=%.2f threats=[%s] (%dms)",
                        skill_id, parsed.verdict.value, parsed.confidence,
                        threat_summary, elapsed_ms,
                    )
                    return parsed
                except LLMRefusalError as e:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    logger.warning(
                        "Skill %s: LLM refused to analyze (content safety filter): %s",
                        skill_id, e,
                    )
                    logger.debug(
                        "Skill %s: verdict=suspicious (LLM refusal) (%dms)",
                        skill_id, elapsed_ms,
                    )
                    return Stage2Result(
                        verdict=Verdict.SUSPICIOUS,
                        summary="LLM refused to analyze — content triggered safety filter",
                        duration_ms=elapsed_ms,
                        status=AnalyzerStatus.FAILED,
                    )
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.warning(
                        "Skill %s: parse error on attempt %d/%d: %s",
                        skill_id, attempt, self._max_retries, e,
                    )
                except openai.APIStatusError as e:
                    logger.warning(
                        "Skill %s: API status error on attempt %d/%d: %s (status=%s)",
                        skill_id, attempt, self._max_retries, e.message,
                        e.status_code,
                    )
                    # Don't retry on 400 (bad request / input too long)
                    if e.status_code == 400:
                        break
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)
                except openai.APIConnectionError as e:
                    logger.warning(
                        "Skill %s: API connection error on attempt %d/%d: %s",
                        skill_id, attempt, self._max_retries, e,
                    )
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)
                except openai.AuthenticationError as e:
                    logger.error(
                        "Skill %s: authentication failed: %s", skill_id, e)
                    break
                except Exception as e:
                    logger.error(
                        "Skill %s: unexpected error on attempt %d/%d: %s: %s",
                        skill_id, attempt, self._max_retries,
                        type(e).__name__, e,
                    )
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.debug(
            "Skill %s: verdict=suspicious (all retries exhausted) (%dms)",
            skill_id, elapsed_ms,
        )
        return Stage2Result(
            verdict=Verdict.SUSPICIOUS,
            summary="Analysis failed after retries",
            duration_ms=elapsed_ms,
            status=AnalyzerStatus.FAILED,
        )

    def _build_prompt(
        self, content: str, matched_rules: list[RuleMatch],
        ti_entities: list[TIEntityResult] | None = None,
    ) -> str:
        escaped = content[:_MAX_CONTENT_LENGTH]

        if not matched_rules:
            rules_desc = "None"
        else:
            # Deduplication strategy:
            # - CRITICAL: include ALL matches (up to _MAX_CRITICAL_PER_RULE per rule_id),
            #   with a longer evidence window (400 chars) so compound patterns like
            #   "foreignObject + cookie theft + fetch(external URL)" are fully visible.
            # - Non-CRITICAL: keep one example per rule_id with 100-char truncation.
            critical_counts: dict[str, int] = {}
            seen_non_critical: dict[str, bool] = {}
            selected: list[RuleMatch] = []

            for m in matched_rules:
                if m.severity == Severity.CRITICAL:
                    count = critical_counts.get(m.rule_id, 0)
                    if count < _MAX_CRITICAL_PER_RULE:
                        selected.append(m)
                        critical_counts[m.rule_id] = count + 1
                else:
                    if m.rule_id not in seen_non_critical:
                        selected.append(m)
                        seen_non_critical[m.rule_id] = True

            selected = selected[:_MAX_RULES_IN_PROMPT]
            lines = []
            for m in selected:
                if m.severity == Severity.CRITICAL:
                    snippet = m.matched_text[:400]
                else:
                    snippet = m.matched_text[:100]
                location = f" in {m.source_file}" if m.source_file else ""
                lines.append(
                    f"- [{m.rule_id}] {m.rule_name} ({m.severity.value}){location}: "
                    f"matched \"{snippet}\""
                )
            omitted = len(matched_rules) - len(selected)
            if omitted > 0:
                lines.append(f"- ... and {omitted} more matches omitted")
            rules_desc = "\n".join(lines)

        # Format TI results
        ti_desc = self._format_ti_results(ti_entities or [])

        return self._prompt_template.safe_substitute(
            skill_content=escaped,
            matched_rules=rules_desc,
            ti_results=ti_desc,
        )

    @staticmethod
    def _format_ti_results(ti_entities: list[TIEntityResult]) -> str:
        if not ti_entities:
            return "No IOC entities found or TI lookup not performed."

        by_value: dict[str, TIEntityResult] = {}
        for entity in ti_entities:
            by_value.setdefault(entity.entity, entity)

        covered: set[str] = set()
        lines: list[str] = []

        for entity in ti_entities:
            if entity.entity in covered:
                continue
            if entity.kind != "domain_or_url" or "://" not in entity.entity:
                continue

            parts = [f"url={entity.entity}: {SemanticAnalyzer._format_ti_fact(entity)}"]
            covered.add(entity.entity)

            try:
                hostname = (urlparse(entity.entity).hostname or "").lower()
            except Exception:
                hostname = ""

            if hostname:
                try:
                    ipaddress.ip_address(hostname)
                    ip_entity = by_value.get(hostname)
                    if ip_entity and ip_entity.kind == "ip":
                        parts.append(
                            f"ip={hostname}: {SemanticAnalyzer._format_ti_fact(ip_entity)}"
                        )
                        covered.add(hostname)
                except ValueError:
                    domain_entity = by_value.get(hostname)
                    if domain_entity and domain_entity.kind == "domain_or_url":
                        parts.append(
                            f"domain={hostname}: {SemanticAnalyzer._format_ti_fact(domain_entity)}"
                        )
                        covered.add(hostname)

            lines.append(f"- {'; '.join(parts)}")

        for entity in ti_entities:
            if entity.entity in covered:
                continue
            kind = "ip" if entity.kind == "ip" else "domain"
            lines.append(f"- {kind}={entity.entity}: {SemanticAnalyzer._format_ti_fact(entity)}")

        return "\n".join(lines)

    @staticmethod
    def _format_ti_fact(entity: TIEntityResult) -> str:
        parts = [f"risk={entity.risk}"]
        family_names: list[str] = []
        for tag in entity.tags:
            for family in tag.get("malicious_family", []):
                name = family.get("name")
                if name:
                    family_names.append(name)
        if family_names:
            parts.append(f"families={', '.join(family_names)}")
        if entity.decoded_from:
            parts.append("decoded_from=base64")
        return "; ".join(parts)

    async def _call_llm(self, prompt: str) -> dict[str, Any]:
        response = await self._client.chat.completions.create(
            model=self._model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.choices[0].message.content
        if not raw or not raw.strip():
            raise ValueError("LLM returned empty response")
        text = raw.strip()
        # Detect LLM refusal before attempting JSON parse
        text_lower = text.lower()
        if not text_lower.startswith("{") and any(p in text_lower for p in _REFUSAL_PATTERNS):
            raise LLMRefusalError(f"LLM refused to analyze: {text[:200]}")
        return self._extract_json(text)

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        """Extract JSON from LLM response, handling various formats."""
        import re

        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Extract from markdown code block (```json ... ``` or ``` ... ```)
        code_block = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
        if code_block:
            try:
                return json.loads(code_block.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Extract first JSON object by finding balanced braces
        brace_start = text.find("{")
        if brace_start != -1:
            depth = 0
            for i in range(brace_start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[brace_start:i + 1])
                        except json.JSONDecodeError:
                            break

        raise json.JSONDecodeError(
            f"No valid JSON found in LLM response: {text[:200]}...",
            text, 0,
        )

    @staticmethod
    def _parse_response(data: dict[str, Any], elapsed_ms: int) -> Stage2Result:
        verdict_str = data["verdict"].upper()
        verdict_map = {
            "MALICIOUS": Verdict.MALICIOUS,
            "SUSPICIOUS": Verdict.SUSPICIOUS,
            "BENIGN": Verdict.CLEAN,
            "CLEAN": Verdict.CLEAN,
        }
        verdict = verdict_map.get(verdict_str, Verdict.SUSPICIOUS)

        threats = []
        for t in data.get("threats", []):
            threat_cat = _THREAT_CATEGORY_MAP.get(t.get("type", ""))
            severity = _SEVERITY_MAP.get(t.get("severity", "").upper())
            if threat_cat and severity:
                threats.append(Threat(
                    category=threat_cat,
                    severity=severity,
                    evidence=t.get("evidence", ""),
                    explanation=t.get("explanation", ""),
                ))

        return Stage2Result(
            verdict=verdict,
            confidence=float(data.get("confidence", 0.0)),
            threats=threats,
            summary=data.get("summary", ""),
            duration_ms=elapsed_ms,
            status=AnalyzerStatus.COMPLETED,
        )
