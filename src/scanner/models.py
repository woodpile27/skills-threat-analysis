"""Data models for the prompt injection scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    SAFE = "safe"


class ThreatCategory(Enum):
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    HARDCODED_SECRETS = "hardcoded_secrets"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    OBFUSCATION = "obfuscation"
    SOCIAL_ENGINEERING = "social_engineering"
    RESOURCE_ABUSE = "resource_abuse"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALICIOUS_GUIDANCE = "malicious_guidance"
    SKILL_MD_MISMATCH = "skill_md_mismatch"
    CODE_QUALITY = "code_quality"
    BYTECODE_TAMPERING = "bytecode_tampering"
    TRIGGER_HIJACKING = "trigger_hijacking"
    UNICODE_STEGANOGRAPHY = "unicode_steganography"
    TRANSITIVE_TRUST_ABUSE = "transitive_trust_abuse"


class RecommendedAction(Enum):
    BLOCK = "block"
    REVIEW = "review"
    ALLOW = "allow"


class AnalyzerStatus(Enum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMEOUT = "timeout"


# Backward compatibility alias
ThreatType = ThreatCategory


@dataclass
class SkillFileSegment:
    """A single file within a skill package, used for per-file scanning."""
    rel_path: str    # Relative path within skill_dir, e.g. "SKILL.md" or "scripts/run.js"
    content: str
    is_entry: bool = False


@dataclass
class SkillFile:
    id: str
    source: str
    file_path: str
    content: str
    size_bytes: int
    name: str = ""
    entry_file: str = ""
    skill_dir: str = ""
    file_md5s: dict[str, str] = field(default_factory=dict)
    file_sha1s: dict[str, str] = field(default_factory=dict)
    package_md5: str = ""
    package_sha1: str = ""
    # Per-file segments for Stage 1 per-file scanning (populated by loader)
    files: list[SkillFileSegment] = field(default_factory=list)


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: Severity
    matched_text: str
    position: tuple[int, int]
    pattern: str = ""        # Original regex pattern string
    source_file: str = ""    # rel_path of the file where match was found
    ti_note: str = ""        # TI adjustment note (includes original severity)
    ti_ioc: str = ""         # Base IOC (hostname/IP) that triggered de-escalation, for verdict dedup


@dataclass
class Threat:
    category: ThreatCategory
    severity: Severity
    evidence: str
    explanation: str


@dataclass
class Stage1Result:
    verdict: Verdict
    matched_rules: list[RuleMatch] = field(default_factory=list)
    duration_ms: int = 0


@dataclass
class TIEntityResult:
    """A single IOC entity with its TI lookup result."""
    entity: str              # IOC value (IP, domain, or URL)
    kind: str                # "ip" or "domain_or_url"
    risk: str                # "black", "suspicious", "white", "unknown"
    tags: list[dict] = field(default_factory=list)
    source_file: str = ""    # Relative path of the file where entity was found
    position: tuple[int, int] = (0, 0)  # (start, end) character offset in source file
    decoded_from: str = ""   # Non-empty if entity was extracted from a base64-encoded payload


@dataclass
class StageTIResult:
    """Result of the Threat Intelligence lookup stage."""
    verdict: Verdict
    entities: list[TIEntityResult] = field(default_factory=list)
    duration_ms: int = 0
    status: AnalyzerStatus = AnalyzerStatus.COMPLETED
    error: str = ""


@dataclass
class Stage2Result:
    verdict: Verdict
    confidence: float = 0.0
    threats: list[Threat] = field(default_factory=list)
    summary: str = ""
    duration_ms: int = 0
    status: AnalyzerStatus = AnalyzerStatus.COMPLETED


@dataclass
class ScanResult:
    skill: SkillFile
    stage1: Optional[Stage1Result] = None
    stage_ti: Optional[StageTIResult] = None
    stage2: Optional[Stage2Result] = None
    final_verdict: Verdict = Verdict.CLEAN


@dataclass
class ScanSummary:
    scan_id: str
    timestamp: str
    total_scanned: int = 0
    clean: int = 0
    suspicious: int = 0
    malicious: int = 0
    suspicious_skills: list[str] = field(default_factory=list)
    malicious_skills: list[str] = field(default_factory=list)
    threat_type_counts: dict[str, int] = field(default_factory=dict)
    threat_type_skills: dict[str, list[str]] = field(default_factory=dict)
    source_breakdown: dict[str, dict] = field(default_factory=dict)
