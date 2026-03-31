"""Stage 3: Result aggregation and report generation.

Outputs per-skill reports conforming to the QAX ScanReport schema v2.0,
covering only the `static` (Stage 1) and `llm_semantic` (Stage 2) analyzers.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from scanner.models import (
    AnalyzerStatus,
    RecommendedAction,
    ScanResult,
    ScanSummary,
    Severity,
    SkillFile,
    StageTIResult,
    TIEntityResult,
    Verdict,
)

# Map rule_name → ThreatCategory value for static findings.
# Falls back to rule_name itself if not found.
_RULE_CATEGORY_MAP = {
    # PI-001~007 (original rules)
    "instruction_override": "prompt_injection",
    "role_hijacking": "prompt_injection",
    "system_prompt_manipulation": "prompt_injection",
    "context_exfiltration": "data_exfiltration",
    "steganographic_injection": "unicode_steganography",
    "dangerous_operation": "command_injection",
    "social_engineering_injection": "social_engineering",
    # PI-008~014 (from skill-scan-1.0.0)
    "credential_access": "hardcoded_secrets",
    "network_exfiltration": "data_exfiltration",
    "filesystem_destruction": "command_injection",
    "obfuscation_standalone": "obfuscation",
    "crypto_wallet_access": "data_exfiltration",
    "persistence_mechanism": "command_injection",
    "privilege_escalation": "privilege_escalation",
    # PA-001~006 (advanced analyzer)
    "invisible_unicode_density": "unicode_steganography",
    "invisible_unicode_hidden_injection": "unicode_steganography",
    "homoglyph_attack": "unicode_steganography",
    "mixed_scripts_latin_cyrillic": "unicode_steganography",
    "mixed_scripts_multi": "unicode_steganography",
    "markdown_hidden_instruction": "prompt_injection",
    "markdown_data_uri": "obfuscation",
    "gradual_escalation": "social_engineering",
    "encoded_payload_base64": "obfuscation",
    "encoded_payload_rot13": "obfuscation",
    # PI-015~017
    "trigger_hijacking": "trigger_hijacking",
    "remote_binary_download": "supply_chain_attack",
    "svg_html_xss": "data_exfiltration",
}

# Map ThreatCategory value → ThreatCategory value for LLM findings.
_THREAT_CATEGORY_MAP = {
    "instruction_override": "prompt_injection",
    "role_hijacking": "prompt_injection",
    "system_prompt_manipulation": "prompt_injection",
    "context_exfiltration": "data_exfiltration",
    "steganographic_injection": "unicode_steganography",
    "dangerous_operation": "command_injection",
    "social_engineering": "social_engineering",
    # Direct category names (LLM may return these directly)
    "prompt_injection": "prompt_injection",
    "command_injection": "command_injection",
    "data_exfiltration": "data_exfiltration",
    "hardcoded_secrets": "hardcoded_secrets",
    "obfuscation": "obfuscation",
    "privilege_escalation": "privilege_escalation",
    "unicode_steganography": "unicode_steganography",
}

# Chinese title/description templates for LLM semantic findings, keyed by ThreatCategory value.
# title_en / description_en carry the original English LLM explanation verbatim.
_LLM_CATEGORY_ZH: dict[str, tuple[str, str]] = {
    "command_injection":      ("LLM 检测: 命令注入",       "LLM 语义分析发现命令注入或危险命令执行模式，可能在目标系统上执行恶意代码。"),
    "prompt_injection":       ("LLM 检测: 提示词注入",     "LLM 语义分析发现提示词注入攻击模式，试图覆盖或绕过 AI 安全指令。"),
    "data_exfiltration":      ("LLM 检测: 数据外泄",       "LLM 语义分析发现数据窃取或外泄模式，可能将敏感数据发送至外部服务器。"),
    "hardcoded_secrets":      ("LLM 检测: 凭证信息泄露",   "LLM 语义分析发现硬编码凭证或密钥访问模式，可能导致认证信息泄露。"),
    "unauthorized_tool_use":  ("LLM 检测: 未授权工具调用", "LLM 语义分析发现未经用户授权的工具或 API 调用行为。"),
    "obfuscation":            ("LLM 检测: 恶意代码混淆",   "LLM 语义分析发现代码混淆模式（如 base64、Unicode 编码），用于规避静态检测。"),
    "social_engineering":     ("LLM 检测: 社会工程学",     "LLM 语义分析发现社会工程学攻击模式，利用权威性或紧迫感诱导用户执行危险操作。"),
    "resource_abuse":         ("LLM 检测: 资源滥用",       "LLM 语义分析发现资源滥用模式，可能占用大量计算或网络资源。"),
    "supply_chain_attack":    ("LLM 检测: 供应链攻击",     "LLM 语义分析发现供应链攻击模式，通过下载并执行外部二进制文件植入恶意载荷。"),
    "privilege_escalation":   ("LLM 检测: 权限提升",       "LLM 语义分析发现权限提升攻击模式，试图获取比正常运行所需更高的系统权限。"),
    "malicious_guidance":     ("LLM 检测: 恶意指导内容",   "LLM 语义分析发现恶意引导内容，可能诱使用户执行有害操作。"),
    "skill_md_mismatch":      ("LLM 检测: 描述与行为不符", "LLM 语义分析发现 SKILL.md 的功能描述与实际行为存在明显不一致，疑似伪装欺骗。"),
    "code_quality":           ("LLM 检测: 代码质量问题",   "LLM 语义分析发现代码质量或安全实践问题。"),
    "bytecode_tampering":     ("LLM 检测: 字节码篡改",     "LLM 语义分析发现预编译字节码或字节码篡改模式，可能隐藏恶意逻辑。"),
    "trigger_hijacking":      ("LLM 检测: 触发器劫持",     "LLM 语义分析发现触发器劫持模式，试图在 Skill 加载时自动执行代码或独占工具调用。"),
    "unicode_steganography":  ("LLM 检测: Unicode 隐写",   "LLM 语义分析发现 Unicode 隐写攻击，利用不可见字符或双向控制符隐藏恶意指令。"),
    "transitive_trust_abuse": ("LLM 检测: 传递信任滥用",   "LLM 语义分析发现传递信任滥用模式，借助可信组件执行未经授权的恶意操作。"),
}

# Chinese title/description templates for TI findings, keyed by risk level.
_TI_RISK_ZH: dict[str, tuple[str, str]] = {
    "black": (
        "威胁情报: 恶意指标",
        "威胁情报查询发现已知恶意 IOC（黑名单命中），该实体已被标记为恶意。",
    ),
    "suspicious": (
        "威胁情报: 可疑指标",
        "威胁情报查询发现可疑 IOC，该实体存在恶意行为嫌疑。",
    ),
}

_TI_REMEDIATION = (
    "拒绝安装此 Skill。该 Skill 包含已知恶意或可疑的 IP/域名/URL，"
    "威胁情报系统已将其标记为恶意指标。若已安装，请立即审查网络访问日志并隔离相关资源。"
)


# Chinese names for rule_name values (Stage 1 findings).
_RULE_NAME_ZH: dict[str, str] = {
    "instruction_override":           "指令覆盖",
    "role_hijacking":                 "角色劫持",
    "system_prompt_manipulation":     "系统提示词操控",
    "context_exfiltration":           "上下文窃取",
    "steganographic_injection":       "隐写注入",
    "dangerous_operation":            "危险操作",
    "social_engineering_injection":   "社会工程学注入",
    "credential_access":              "凭证访问",
    "network_exfiltration":           "网络外泄",
    "filesystem_destruction":         "文件系统破坏",
    "obfuscation_standalone":         "代码混淆",
    "crypto_wallet_access":           "加密钱包访问",
    "persistence_mechanism":          "持久化机制",
    "privilege_escalation":           "权限提升",
    "invisible_unicode_density":      "不可见 Unicode 密度异常",
    "invisible_unicode_hidden_injection": "Unicode 隐写注入",
    "homoglyph_attack":               "同形字攻击",
    "mixed_scripts_latin_cyrillic":   "多语言混合脚本（拉丁/西里尔）",
    "mixed_scripts_multi":            "多语言混合脚本",
    "markdown_hidden_instruction":    "Markdown 隐藏指令",
    "markdown_data_uri":              "Markdown 数据 URI",
    "gradual_escalation":             "渐进式升级攻击",
    "encoded_payload_base64":         "Base64 编码载荷",
    "encoded_payload_rot13":          "ROT13 编码载荷",
    "trigger_hijacking":              "触发器劫持",
    "remote_binary_download":         "远程二进制下载",
    "svg_html_xss":                   "SVG/HTML XSS 注入",
}

# Chinese names for ThreatCategory values (used in summary).
_CATEGORY_ZH: dict[str, str] = {
    "prompt_injection":       "提示词注入",
    "command_injection":      "命令注入",
    "data_exfiltration":      "数据外泄",
    "hardcoded_secrets":      "凭证信息泄露",
    "obfuscation":            "代码混淆",
    "privilege_escalation":   "权限提升",
    "unicode_steganography":  "Unicode 隐写",
    "social_engineering":     "社会工程学",
    "supply_chain_attack":    "供应链攻击",
    "trigger_hijacking":      "触发器劫持",
    "unauthorized_tool_use":  "未授权工具调用",
    "resource_abuse":         "资源滥用",
    "malicious_guidance":     "恶意指导内容",
    "skill_md_mismatch":      "描述与行为不符",
    "code_quality":           "代码质量问题",
    "bytecode_tampering":     "字节码篡改",
    "transitive_trust_abuse": "传递信任滥用",
}

# Remediation advice per ThreatCategory value.
_CATEGORY_REMEDIATION: dict[str, str] = {
    "prompt_injection":
        "拒绝安装此 Skill。该 Skill 包含试图覆盖或绕过 AI 安全指令的提示词注入代码，"
        "可能诱导 Claude 执行未经授权的操作。建议向 Skill 发布平台举报。",
    "command_injection":
        "拒绝安装此 Skill。立即删除所有危险 Shell 命令（curl|bash、wget|sh、"
        "base64 解码执行等），切勿在终端中执行 Skill 提供的任何未知命令。"
        "若已执行，请立即检查系统是否被植入恶意程序。",
    "data_exfiltration":
        "拒绝安装此 Skill。该 Skill 包含将本地数据（凭证、Cookie、会话信息等）"
        "发送至外部服务器的代码。若已安装，请立即轮换所有相关凭证并审查网络访问日志。",
    "hardcoded_secrets":
        "立即轮换所有已泄露的凭证、API Key 或密码。"
        "从代码中移除所有硬编码的密钥，改用环境变量或专用密钥管理服务存储敏感信息。",
    "obfuscation":
        "拒绝安装此 Skill。代码中存在 Base64、ROT13 或其他编码混淆，"
        "解码后将执行恶意载荷。不应信任任何包含无法直接阅读的编码执行逻辑的 Skill。",
    "privilege_escalation":
        "拒绝安装此 Skill。该 Skill 尝试提升系统权限（如修改 sudoers、chmod +s 等），"
        "可能被用于建立持久化恶意访问。若已安装，请立即审查系统权限变更记录。",
    "unicode_steganography":
        "拒绝安装此 Skill。该 Skill 使用不可见 Unicode 字符或同形字隐藏恶意指令，"
        "是针对 AI 系统的高级攻击手段，肉眼无法直接识别，必须拒绝安装。",
    "social_engineering":
        "拒绝安装此 Skill。该 Skill 使用虚假权威声明、紧迫感或欺骗性内容诱导用户执行危险操作，"
        "切勿按照 Skill 提示在终端中执行任何命令。",
    "supply_chain_attack":
        "拒绝安装此 Skill。该 Skill 尝试从外部下载并执行二进制文件，"
        "是典型的供应链攻击载体，可能在系统上植入后门或恶意软件。"
        "若已执行下载命令，请立即隔离主机并进行安全排查。",
    "trigger_hijacking":
        "拒绝安装此 Skill。该 Skill 声称独占工具调用或在加载时自动执行代码，"
        "可能劫持其他合法 Skill 的功能或在无用户确认的情况下触发操作。",
    "unauthorized_tool_use":
        "审查该 Skill 的工具使用范围，确保其仅调用 SKILL.md 中已声明的工具。"
        "移除所有超出声明范围的工具调用代码，并在受限环境中重新测试后再部署。",
    "resource_abuse":
        "为该 Skill 添加速率限制和配额控制，防止其占用过多计算或网络资源。"
        "审查并限制其可访问的外部端点和调用频率。",
    "malicious_guidance":
        "拒绝安装此 Skill。该 Skill 包含引导用户执行有害操作的内容，"
        "不应被信任或部署到任何生产环境中。建议向平台举报。",
    "skill_md_mismatch":
        "拒绝安装此 Skill。SKILL.md 的功能描述与实际代码行为存在明显不一致，"
        "是典型的伪装欺骗特征。发布者可能故意隐瞒了真实的恶意功能。",
    "code_quality":
        "修复代码中的安全问题，包括输入验证、错误处理和不安全的 API 使用方式。"
        "建议在代码审查通过并修复所有高危问题后，再重新发布该 Skill。",
    "bytecode_tampering":
        "拒绝安装此 Skill。该 Skill 包含预编译字节码或被篡改的字节码文件，"
        "可能隐藏无法通过源码审查发现的恶意逻辑，必须拒绝安装。",
    "transitive_trust_abuse":
        "拒绝安装此 Skill。该 Skill 利用可信组件的信任关系执行未经授权的操作，"
        "应对所有依赖的第三方组件进行完整的安全审查后才可考虑安装。",
}

# Severity string used in the schema (uppercase).
_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
    Severity.SAFE: "SAFE",
}

# Severity ordering for sorting (higher = more severe).
_SEVERITY_ORDER = {
    Severity.CRITICAL: 6,
    Severity.HIGH: 5,
    Severity.MEDIUM: 4,
    Severity.LOW: 3,
    Severity.INFO: 2,
    Severity.SAFE: 1,
}


def _make_finding_id(rule_id: str, file_path: str, line_number: int) -> str:
    """Generate deterministic finding ID: f_{rule_id}_{8-char hash}."""
    raw = f"{rule_id}:{file_path}:{line_number}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"f_{rule_id}_{h}"


def _offset_to_line(content: str, offset: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return content[:offset].count("\n") + 1


def _get_context(content: str, start: int, end: int, lines: int = 2) -> tuple[str, str]:  # noqa: ARG001
    """Extract context_before and context_after around [start, end)."""
    all_lines = content.splitlines(keepends=True)
    line_no = content[:start].count("\n")  # 0-based

    # context_before: up to `lines` lines before the match line
    before_start = max(0, line_no - lines)
    before = "".join(all_lines[before_start:line_no]).rstrip("\n")

    # context_after: up to `lines` lines after the match line
    after_start = line_no + 1
    after_end = min(len(all_lines), after_start + lines)
    after = "".join(all_lines[after_start:after_end]).rstrip("\n")

    return before, after


def _get_snippet(content: str, start: int, end: int) -> str:
    """Get the full line containing the match as snippet."""
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end].strip()


def _compute_files_hash(
    file_hashes: dict[str, str], algo: str, package_hash: str = ""
) -> str:
    """Compute aggregate hash per spec §6.2-6.3.

    Prepend package_hash (empty string for directory-loaded skills),
    then sorted per-file hashes, then hash the concatenation.
    """
    parts = [package_hash] + [file_hashes[k] for k in sorted(file_hashes)]
    combined = "".join(parts)
    if not combined:
        return ""
    if algo == "md5":
        return hashlib.md5(combined.encode()).hexdigest()
    return hashlib.sha1(combined.encode()).hexdigest()


_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?\n)---", re.DOTALL)


def _parse_frontmatter(content: str) -> dict[str, Any]:
    """Extract metadata from YAML frontmatter (``--- ... ---``) at the top of *content*."""
    m = _FRONTMATTER_RE.match(content)
    if not m:
        return {}
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict):
        return {}

    result: dict[str, Any] = {}
    if "name" in data:
        result["name"] = str(data["name"])
    if "description" in data:
        result["description"] = str(data["description"])
    if "trigger" in data:
        result["trigger"] = str(data["trigger"])
    if "author" in data:
        result["author"] = str(data["author"])

    version = data.get("version")
    if version is None and isinstance(data.get("metadata"), dict):
        version = data["metadata"].get("version")
    if version is not None:
        result["version"] = str(version)

    return result


def _resolve_entry_file_path(skill: SkillFile) -> str:
    """Return the relative path of the skill's entry file for use in findings location.

    Returns a path relative to skill_dir so it matches keys in files_sha1s/files_md5s,
    e.g. ``SKILL.md`` or ``!security-clawsight/SKILL.md`` for multi-skill ZIPs.
    """
    if skill.entry_file:
        rel = skill.entry_file
    else:
        fp = skill.file_path
        if fp.startswith(("http://", "https://")):
            path_part = urlparse(fp).path.rstrip("/")
            rel = path_part.rsplit("/", 1)[-1] if "/" in path_part else (path_part or "SKILL.md")
        elif skill.skill_dir:
            try:
                rel = Path(fp).relative_to(skill.skill_dir).as_posix()
            except ValueError:
                rel = Path(fp).name
        else:
            rel = Path(fp).name

    return rel


class Reporter:
    def __init__(self, output_dir: str | Path, *, report_all_skills: bool = False):
        self._output_dir = Path(output_dir)
        self._threats_dir = self._output_dir / "threats"
        self._threats_dir.mkdir(parents=True, exist_ok=True)
        self._clean_dir = self._output_dir / "clean"
        self._report_all_skills = report_all_skills

    def generate(self, scan_id: str, results: list[ScanResult]) -> ScanSummary:
        summary = self._build_summary(scan_id, results)
        self._write_threat_reports(results, scan_id)
        self._write_summary_json(summary)
        self._write_summary_md(summary, results)
        return summary

    def generate_reports(
        self,
        scan_id: str,
        results: list[ScanResult],
        reports_dir: Path,
    ) -> ScanSummary:
        """Write all per-skill reports to a flat *reports_dir/* directory.

        Unlike ``generate()``, which separates findings into ``threats/`` and
        ``clean/``, this method writes every skill's report into the single
        *reports_dir* folder regardless of verdict.  ``summary.json`` and
        ``summary.md`` are written to the Reporter's output directory as usual.
        """
        summary = self._build_summary(scan_id, results)
        reports_dir.mkdir(parents=True, exist_ok=True)
        for r in results:
            report = self._build_skill_report(r, scan_id)
            (reports_dir / f"{r.skill.id}.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        self._write_summary_json(summary)
        self._write_summary_md(summary, results)
        return summary

    def write_batch(
        self,
        scan_id: str,
        batch_results: list[ScanResult],
        all_results: list[ScanResult],
        reports_dir: Path,
    ) -> ScanSummary:
        """Incrementally write per-skill reports for *batch_results* only.

        Used by the batch CLI to write reports as each Stage 2 batch (or the
        Stage 1-only group) completes, rather than rewriting everything each time.
        ``summary.json`` and ``summary.md`` are always rewritten based on the
        current state of *all_results* (which may include skills still awaiting
        Stage 2).
        """
        reports_dir.mkdir(parents=True, exist_ok=True)
        for r in batch_results:
            report = self._build_skill_report(r, scan_id)
            (reports_dir / f"{r.skill.id}.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        summary = self._build_summary(scan_id, all_results)
        self._write_summary_json(summary)
        self._write_summary_md(summary, all_results)
        return summary

    def build_skill_report(self, result: ScanResult, scan_id: str) -> dict[str, Any]:
        """Build a QAX report dict for a single skill without writing to disk.

        This is the public API consumed by the worker mode (MongoDB reporter).
        """
        return self._build_skill_report(result, scan_id)

    # ------------------------------------------------------------------ #
    #  Per-skill report (QAX ScanReport schema v2.0)
    # ------------------------------------------------------------------ #

    def _write_threat_reports(self, results: list[ScanResult], scan_id: str) -> None:
        for r in results:
            has_stage1_findings = bool(
                r.stage1 and r.stage1.matched_rules)
            has_ti_findings = bool(
                r.stage_ti and any(
                    e.risk in ("black", "suspicious") for e in r.stage_ti.entities))
            has_stage2_findings = bool(
                r.stage2 and r.stage2.threats)
            has_non_clean_verdict = r.final_verdict in (
                Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            has_findings = (
                has_non_clean_verdict or has_stage1_findings
                or has_ti_findings or has_stage2_findings
            )

            if has_findings:
                report = self._build_skill_report(r, scan_id)
                path = self._threats_dir / f"{r.skill.id}.json"
                path.write_text(
                    json.dumps(report, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            elif self._report_all_skills:
                self._clean_dir.mkdir(parents=True, exist_ok=True)
                report = self._build_skill_report(r, scan_id)
                path = self._clean_dir / f"{r.skill.id}.json"
                path.write_text(
                    json.dumps(report, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )

    def _build_skill_report(self, r: ScanResult, scan_id: str) -> dict[str, Any]:
        """Build a single-skill report conforming to the QAX schema."""
        now = datetime.now(timezone.utc)
        content = r.skill.content

        # Build findings from both stages
        findings: list[dict[str, Any]] = []
        entry_file_path = _resolve_entry_file_path(r.skill)

        # Build per-file content map for accurate line-number resolution.
        # Keys are rel_path values matching RuleMatch.source_file.
        seg_content_map: dict[str, str] = {
            s.rel_path: s.content for s in r.skill.files
        } if r.skill.files else {}

        # --- Static findings (Stage 1) ---
        if r.stage1 and r.stage1.matched_rules:
            for m in r.stage1.matched_rules:
                # Resolve the actual source file content and path.
                # file_rel is relative to skill_dir, matching files_sha1s keys.
                if m.source_file and m.source_file in seg_content_map:
                    seg_content = seg_content_map[m.source_file]
                    file_rel = m.source_file
                else:
                    # Fallback: combined content (legacy path, source_file not set)
                    seg_content = content
                    file_rel = r.skill.entry_file or entry_file_path

                actual_file_path = file_rel

                line_no = _offset_to_line(seg_content, m.position[0])
                snippet = _get_snippet(seg_content, m.position[0], m.position[1])
                ctx_before, ctx_after = _get_context(
                    seg_content, m.position[0], m.position[1])
                category = _RULE_CATEGORY_MAP.get(m.rule_name, m.rule_name)
                fid = _make_finding_id(m.rule_id, actual_file_path, line_no)

                rule_name_zh = _RULE_NAME_ZH.get(m.rule_name, m.rule_name)
                matched_preview = m.matched_text[:120].replace("\n", " ")
                findings.append({
                    "id": fid,
                    "rule_id": m.rule_id,
                    "analyzer_id": "static",
                    "category": category,
                    "severity": _SEVERITY_LABEL[m.severity],
                    "title": f"规则匹配: {m.rule_id} ({rule_name_zh}) — {matched_preview}",
                    "description": (
                        f"在 {actual_file_path} 第 {line_no} 行检测到{rule_name_zh}类型的可疑模式。\n\n"
                        f"匹配内容：{m.matched_text[:400]}"
                    ),
                    "title_en": f"Rule Match: {m.rule_id} ({m.rule_name}) — {matched_preview}",
                    "description_en": (
                        f"Detected suspicious pattern of type {m.rule_name} "
                        f"at {actual_file_path} line {line_no}.\n\n"
                        f"Matched content: {m.matched_text[:400]}"
                    ),
                    "location": {
                        "file_path": actual_file_path,
                        "line_number": line_no,
                        "line_end": None,
                        "column_start": None,
                        "snippet": snippet[:500],
                    },
                    "remediation": _CATEGORY_REMEDIATION.get(category),
                    "evidence": {
                        "matched_pattern": m.pattern,
                        "matched_content": m.matched_text[:500],
                        "context_before": ctx_before[:500],
                        "context_after": ctx_after[:500],
                    },
                    "threat_intel": None,
                    "metadata": {},
                    "references": [],
                })

        # --- LLM Semantic findings (Stage 2) ---
        if r.stage2 and r.stage2.threats:
            for t in r.stage2.threats:
                rule_id = f"LLM_{t.category.value.upper()}"
                category = _THREAT_CATEGORY_MAP.get(
                    t.category.value, t.category.value)
                fid = _make_finding_id(rule_id, entry_file_path, 0)

                zh_title, zh_desc = _LLM_CATEGORY_ZH.get(
                    t.category.value,
                    (f"LLM 检测: {t.category.value}", f"LLM 语义分析发现 {t.category.value} 类型威胁。"),
                )
                en_explanation = t.explanation or ""

                evidence_preview = (t.evidence or "")[:120].replace("\n", " ")
                full_zh_desc = (
                    f"{zh_desc}\n\n{en_explanation}" if en_explanation else zh_desc
                )
                findings.append({
                    "id": fid,
                    "rule_id": rule_id,
                    "analyzer_id": "llm_semantic",
                    "category": category,
                    "severity": _SEVERITY_LABEL[t.severity],
                    "title": f"{zh_title} — {evidence_preview}" if evidence_preview else zh_title,
                    "description": full_zh_desc,
                    "title_en": en_explanation[:100] if en_explanation else f"LLM: {t.category.value}",
                    "description_en": en_explanation,
                    "location": {
                        "file_path": entry_file_path,
                        "line_number": 0,
                        "line_end": None,
                        "column_start": None,
                        "snippet": t.evidence[:500] if t.evidence else "",
                    },
                    "evidence": {
                        "matched_pattern": "llm_semantic_analysis",
                        "matched_content": t.evidence[:500] if t.evidence else "",
                        "context_before": "",
                        "context_after": "",
                    },
                    "threat_intel": None,
                    "remediation": _CATEGORY_REMEDIATION.get(category),
                    "metadata": {"llm_generated": True},
                    "references": [],
                })

        # --- Threat Intelligence findings (Stage TI) ---
        if r.stage_ti and r.stage_ti.entities:
            for ent in r.stage_ti.entities:
                if ent.risk not in ("black", "suspicious"):
                    continue
                severity = "CRITICAL" if ent.risk == "black" else "HIGH"
                rule_id = f"TI_{ent.kind.upper()}_{ent.risk.upper()}"
                category = "data_exfiltration"
                ti_file_path = ent.source_file or entry_file_path

                # Resolve line number and snippet from position offset
                ti_line_no = 0
                ti_snippet = ent.entity
                ti_ctx_before = ""
                ti_ctx_after = ""
                if ent.position != (0, 0):
                    # Pick the correct content for offset resolution
                    if ent.source_file and ent.source_file in seg_content_map:
                        ti_src_content = seg_content_map[ent.source_file]
                    else:
                        ti_src_content = content
                    ti_line_no = _offset_to_line(ti_src_content, ent.position[0])
                    ti_snippet = _get_snippet(
                        ti_src_content, ent.position[0], ent.position[1])
                    ti_ctx_before, ti_ctx_after = _get_context(
                        ti_src_content, ent.position[0], ent.position[1])

                fid = _make_finding_id(rule_id, ti_file_path, ti_line_no)
                zh_title, zh_desc = _TI_RISK_ZH[ent.risk]

                tag_summary = ""
                if ent.tags:
                    families = []
                    for tag_group in ent.tags:
                        for fam in tag_group.get("malicious_family", []):
                            families.append(fam.get("name", ""))
                    if families:
                        tag_summary = f"关联恶意家族: {', '.join(f for f in families if f)}"

                findings.append({
                    "id": fid,
                    "rule_id": rule_id,
                    "analyzer_id": "threat_intel",
                    "category": category,
                    "severity": severity,
                    "title": f"{zh_title}: {ent.entity}",
                    "description": (
                        f"{zh_desc}\n\n"
                        f"实体: {ent.entity} (类型: {ent.kind}, 风险等级: {ent.risk})\n"
                        f"来源文件: {ti_file_path}"
                        f"{f' 第 {ti_line_no} 行' if ti_line_no else ''}\n"
                        f"{tag_summary}"
                    ),
                    "title_en": f"Threat Intel: {ent.risk} indicator — {ent.entity}",
                    "description_en": (
                        f"TI lookup flagged {ent.entity} ({ent.kind}) as {ent.risk}."
                    ),
                    "location": {
                        "file_path": ti_file_path,
                        "line_number": ti_line_no,
                        "line_end": None,
                        "column_start": None,
                        "snippet": ti_snippet[:500],
                    },
                    "evidence": {
                        "matched_pattern": "threat_intel_lookup",
                        "matched_content": ent.entity,
                        "context_before": ti_ctx_before[:500],
                        "context_after": ti_ctx_after[:500],
                    },
                    "threat_intel": {
                        "entity": ent.entity,
                        "kind": ent.kind,
                        "risk": ent.risk,
                        "tags": ent.tags,
                    },
                    "remediation": _TI_REMEDIATION,
                    "metadata": {"ti_generated": True},
                    "references": [],
                })

        # Sort findings by severity (CRITICAL first)
        findings.sort(
            key=lambda f: -_SEVERITY_ORDER.get(
                Severity(f["severity"].lower()), 0
            )
        )

        # --- Verdict ---
        verdict_obj = self._compute_verdict(r, findings)

        # --- Stats ---
        severity_counter: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counter: Counter[str] = Counter()
        analyzer_counter: Counter[str] = Counter()
        for f in findings:
            severity_counter[f["severity"]] = severity_counter.get(
                f["severity"], 0) + 1
            category_counter[f["category"]] += 1
            analyzer_counter[f["analyzer_id"]] += 1

        stats = {
            "total_findings": len(findings),
            "by_severity": severity_counter,
            "by_category": dict(category_counter),
            "by_analyzer": dict(analyzer_counter),
        }

        # --- Analyzer results ---
        analyzer_results: dict[str, Any] = {}
        if r.stage1:
            static_findings = [
                f for f in findings if f["analyzer_id"] == "static"]
            analyzer_results["static"] = {
                "analyzer_id": "static",
                "status": AnalyzerStatus.COMPLETED.value,
                "duration_ms": r.stage1.duration_ms,
                "findings": static_findings,
                "verdict": r.stage1.verdict.value.upper(),
                "verdict_confidence": 0.0,
                "extra": {
                    "rules_triggered": len(r.stage1.matched_rules),
                    "files_scanned": 1,
                },
                "error": None,
            }
        if r.stage_ti:
            ti_findings = [
                f for f in findings if f["analyzer_id"] == "threat_intel"]
            analyzer_results["threat_intel"] = {
                "analyzer_id": "threat_intel",
                "status": r.stage_ti.status.value,
                "duration_ms": r.stage_ti.duration_ms,
                "findings": ti_findings,
                "verdict": r.stage_ti.verdict.value.upper(),
                "verdict_confidence": 0.0,
                "extra": {
                    "entities_extracted": len(r.stage_ti.entities),
                    "entities_flagged": len(ti_findings),
                },
                "error": r.stage_ti.error or None,
            }
        if r.stage2:
            llm_findings = [
                f for f in findings if f["analyzer_id"] == "llm_semantic"]
            analyzer_results["llm_semantic"] = {
                "analyzer_id": "llm_semantic",
                "status": r.stage2.status.value,
                "duration_ms": r.stage2.duration_ms,
                "findings": llm_findings,
                "verdict": r.stage2.verdict.value.upper(),
                "verdict_confidence": r.stage2.confidence,
                "extra": {
                    "provider": "",
                    "total_batches": 1,
                    "batch_errors": 0,
                    "llm_findings_count": len(llm_findings),
                },
                "error": r.stage2.summary if r.stage2.status == AnalyzerStatus.FAILED else None,
            }

        # --- Total scan duration ---
        total_ms = (r.stage1.duration_ms if r.stage1 else 0) + \
                   (r.stage_ti.duration_ms if r.stage_ti else 0) + \
                   (r.stage2.duration_ms if r.stage2 else 0)

        # --- Determine which analyzers were used ---
        analyzers_used = list(analyzer_results.keys())

        meta = _parse_frontmatter(r.skill.content)
        raw_name = meta.get("name")
        if raw_name:
            skill_name = raw_name
            skill_metadata_name = raw_name
        else:
            # 当 SKILL.md 缺少规范的 frontmatter（没有 name 等字段）时：
            # - skill_name 统一设置为 "skill"，用于对外展示一个通用名称；
            # - skill_metadata.name 保持为空字符串，避免误导下游以为有有效的技能名。
            skill_name = "skill"
            skill_metadata_name = ""

        version_val = meta.get("version", "")
        if not version_val and isinstance(meta.get("metadata"), dict):
            version_val = str(meta["metadata"].get("version", ""))

        return {
            "schema_version": "2.0",
            "scan_id": scan_id,
            "skill_name": skill_name,
            "skill_path": r.skill.skill_dir or r.skill.file_path,
            "scan_timestamp": now.isoformat(),
            "scan_duration_ms": total_ms,
            "verdict": verdict_obj,
            "stats": stats,
            "findings": findings,
            "analyzer_results": analyzer_results,
            "skill_metadata": {
                "name": skill_metadata_name,
                "description": meta.get("description", ""),
                "allowed_tools": [],
                "trigger_description": meta.get("trigger", ""),
                "author": meta.get("author", ""),
                "version": version_val,
                "md5_info": {
                    "files_md5": _compute_files_hash(r.skill.file_md5s, "md5", r.skill.package_md5),
                    "package_md5": r.skill.package_md5,
                    "file_md5s": dict(r.skill.file_md5s),
                },
                "sha1_info": {
                    "files_sha1": _compute_files_hash(r.skill.file_sha1s, "sha1", r.skill.package_sha1),
                    "package_sha1": r.skill.package_sha1,
                    "file_sha1s": dict(r.skill.file_sha1s),
                },
            },
            "scan_config": {
                "name": "balanced",
                "mode": "balanced",
                "disabled_rules": [],
                "severity_overrides": {},
                "disabled_analyzers": [],
                "yara_mode": "balanced",
                "max_findings_per_rule": 5,
                "enable_cross_file": True,
                "sensitive_file_patterns": [],
                "known_test_values": [],
                "file_size_limit_kb": 0,
            },
        }

    def _compute_verdict(
        self, r: ScanResult, findings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Compute verdict combining Stage 1 findings and Stage 2 LLM assessment.

        When Stage 2 LLM has completed:
        - MALICIOUS → trust LLM, MALICIOUS/BLOCK
        - SUSPICIOUS → trust LLM, SUSPICIOUS/REVIEW
        - BENIGN/CLEAN → LLM overrides Stage 1 false positives, CLEAN/ALLOW
        - ERROR → fall back to Stage 1 findings-based logic

        When Stage 2 is absent (stage-1-only mode), use findings-based logic:
        - CRITICAL findings >= 1 → MALICIOUS, BLOCK
        - HIGH findings >= 1 or total >= 3 → SUSPICIOUS, REVIEW
        - Any finding → SUSPICIOUS, REVIEW
        - No findings → CLEAN, ALLOW
        """
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        total = len(findings)

        # Stage 2 LLM verdict takes priority when available and successful
        s2 = r.stage2
        has_llm_verdict = (
            s2 is not None and s2.status == AnalyzerStatus.COMPLETED
        )

        if has_llm_verdict:
            if s2.verdict == Verdict.MALICIOUS:
                result = Verdict.MALICIOUS
                action = RecommendedAction.BLOCK
                confidence = max(0.8, s2.confidence)
            elif s2.verdict == Verdict.SUSPICIOUS:
                result = Verdict.SUSPICIOUS
                action = RecommendedAction.REVIEW
                confidence = s2.confidence
            elif s2.verdict == Verdict.CLEAN:
                if critical >= 1:
                    # LLM says clean but Stage 1 has CRITICAL findings — downgrade
                    # to SUSPICIOUS for human review rather than silently allowing.
                    result = Verdict.SUSPICIOUS
                    action = RecommendedAction.REVIEW
                    confidence = min(s2.confidence, 0.5)
                else:
                    result = Verdict.CLEAN
                    action = RecommendedAction.ALLOW
                    confidence = s2.confidence
            else:
                has_llm_verdict = False

        if not has_llm_verdict:
            if critical >= 1:
                result = Verdict.MALICIOUS
                action = RecommendedAction.BLOCK
                confidence = max(0.8, r.stage2.confidence if r.stage2 else 0.8)
            elif high >= 1 or total >= 3:
                result = Verdict.SUSPICIOUS
                action = RecommendedAction.REVIEW
                confidence = r.stage2.confidence if r.stage2 else 0.6
            elif total > 0:
                result = Verdict.SUSPICIOUS
                action = RecommendedAction.REVIEW
                confidence = r.stage2.confidence if r.stage2 else 0.4
            else:
                result = Verdict.CLEAN
                action = RecommendedAction.ALLOW
                confidence = 1.0

        # Highest severity level (always based on findings, for informational purposes)
        if critical > 0:
            level = "CRITICAL"
        elif high > 0:
            level = "HIGH"
        elif any(f["severity"] == "MEDIUM" for f in findings):
            level = "MEDIUM"
        elif any(f["severity"] == "LOW" for f in findings):
            level = "LOW"
        elif any(f["severity"] == "INFO" for f in findings):
            level = "INFO"
        else:
            level = "SAFE"

        # Build severity breakdown string
        sev_parts = []
        for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cnt = sum(1 for f in findings if f["severity"] == sev_name)
            if cnt > 0:
                sev_parts.append(f"{sev_name} x {cnt}")
        sev_str = "，".join(sev_parts)

        # Category summary
        cat_counter: Counter[str] = Counter()
        for f in findings:
            cat_counter[f["category"]] += 1
        top_cats = "、".join(
            _CATEGORY_ZH.get(c, c) for c, _ in cat_counter.most_common(3)
        )
        top_cats_en = ", ".join(c for c, _ in cat_counter.most_common(3))

        # Key finding IDs: top-3 by severity (findings already sorted)
        key_ids = [f["id"] for f in findings[:3]]

        if result == Verdict.MALICIOUS:
            summary = (
                f"检测到恶意威胁！共发现 {total} 个安全问题（{sev_str}），"
                f"主要威胁类型: {top_cats}。强烈建议拒绝安装该 Skill 包。"
            )
            summary_en = (
                f"Malicious threats detected! Found {total} security issues ({sev_str}), "
                f"primary threat types: {top_cats_en}. Strongly recommend rejecting installation."
            )
        elif result == Verdict.SUSPICIOUS:
            summary = (
                f"检测到可疑行为，共发现 {total} 个安全问题（{sev_str}），"
                f"主要威胁类型: {top_cats}。建议人工审查后决定。"
            )
            summary_en = (
                f"Suspicious behavior detected, found {total} security issues ({sev_str}), "
                f"primary threat types: {top_cats_en}. Recommend manual review."
            )
        elif result == Verdict.CLEAN and total > 0:
            summary = (
                f"规则扫描命中 {total} 个疑似问题（{sev_str}），"
                f"经 LLM 复验判定为安全，属于误报。"
            )
            summary_en = (
                f"Rule scan matched {total} potential issues ({sev_str}), "
                f"but LLM verification determined them as false positives."
            )
        else:
            summary = "未检测到安全威胁。"
            summary_en = "No security threats detected."

        return {
            "result": result.value.upper(),
            "confidence": round(confidence, 2),
            "level": level,
            "summary": summary,
            "summary_en": summary_en,
            "key_finding_ids": key_ids,
            "recommended_action": action.value.upper(),
        }

    # ------------------------------------------------------------------ #
    #  Summary report (batch-level)
    # ------------------------------------------------------------------ #

    def _build_summary(self, scan_id: str, results: list[ScanResult]) -> ScanSummary:
        threat_counter: Counter[str] = Counter()
        threat_skills: dict[str, list[str]] = {}
        source_stats: dict[str, dict] = {}
        clean = suspicious = malicious = 0
        suspicious_skills: list[str] = []
        malicious_skills: list[str] = []

        for r in results:
            v = r.final_verdict
            skill_path = r.skill.file_path
            if v == Verdict.CLEAN:
                clean += 1
            elif v == Verdict.SUSPICIOUS:
                suspicious += 1
                suspicious_skills.append(skill_path)
            elif v == Verdict.MALICIOUS:
                malicious += 1
                malicious_skills.append(skill_path)

            # Count threat types — only for non-clean results
            if v != Verdict.CLEAN:
                # Prefer Stage 2 (LLM) when available,
                # fall back to Stage 1 (rule matches) otherwise.
                if r.stage2 and r.stage2.threats:
                    for t in r.stage2.threats:
                        tcat = t.category.value
                        threat_counter[tcat] += 1
                        threat_skills.setdefault(tcat, []).append(
                            r.skill.file_path)
                elif r.stage1:
                    seen_rules = set()
                    for m in r.stage1.matched_rules:
                        cat = _RULE_CATEGORY_MAP.get(m.rule_name, m.rule_name)
                        if cat not in seen_rules:
                            threat_counter[cat] += 1
                            threat_skills.setdefault(cat, []).append(
                                r.skill.file_path)
                            seen_rules.add(cat)

            # Source breakdown
            src = r.skill.source
            if src not in source_stats:
                source_stats[src] = {"total": 0,
                                     "malicious": 0, "suspicious": 0}
            source_stats[src]["total"] += 1
            if v == Verdict.MALICIOUS:
                source_stats[src]["malicious"] += 1
            elif v == Verdict.SUSPICIOUS:
                source_stats[src]["suspicious"] += 1

        return ScanSummary(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_scanned=len(results),
            clean=clean,
            suspicious=suspicious,
            malicious=malicious,
            suspicious_skills=suspicious_skills,
            malicious_skills=malicious_skills,
            threat_type_counts=dict(threat_counter.most_common()),
            threat_type_skills=threat_skills,
            source_breakdown=source_stats,
        )

    def _write_summary_json(self, summary: ScanSummary) -> None:
        data = {
            "scan_id": summary.scan_id,
            "timestamp": summary.timestamp,
            "total_scanned": summary.total_scanned,
            "results": {
                "clean": summary.clean,
                "suspicious": summary.suspicious,
                "suspicious_skills": summary.suspicious_skills,
                "malicious": summary.malicious,
                "malicious_skills": summary.malicious_skills,
            },
            "top_threat_types": [
                {
                    "type": k,
                    "count": v,
                    "skills": summary.threat_type_skills.get(k, []),
                }
                for k, v in summary.threat_type_counts.items()
            ],
            "source_breakdown": summary.source_breakdown,
        }
        path = self._output_dir / "summary.json"
        path.write_text(json.dumps(data, ensure_ascii=False,
                        indent=2), encoding="utf-8")

    def _write_summary_md(self, summary: ScanSummary, results: list[ScanResult]) -> None:
        lines = [
            f"# Scan Report: {summary.scan_id}",
            "",
            f"**Timestamp**: {summary.timestamp}",
            f"**Total Scanned**: {summary.total_scanned}",
            "",
            "## Results Overview",
            "",
            "| Category | Count |",
            "|----------|-------|",
            f"| Clean | {summary.clean} |",
            f"| Suspicious | {summary.suspicious} |",
            f"| Malicious | {summary.malicious} |",
            "",
        ]

        if summary.malicious_skills:
            lines.append("### Malicious Skills")
            lines.append("")
            for fp in summary.malicious_skills:
                lines.append(f"- `{fp}`")
            lines.append("")

        if summary.suspicious_skills:
            lines.append("### Suspicious Skills")
            lines.append("")
            for fp in summary.suspicious_skills:
                lines.append(f"- `{fp}`")
            lines.append("")

        lines += [
            "## Top Threat Types",
            "",
        ]
        for t_type, count in summary.threat_type_counts.items():
            skill_files = summary.threat_type_skills.get(t_type, [])
            lines.append(f"### {t_type} ({count})")
            lines.append("")
            if skill_files:
                for fp in skill_files:
                    lines.append(f"- `{fp}`")
            else:
                lines.append("- (none)")
            lines.append("")

        lines += [
            "",
            "## Source Breakdown",
            "",
            "| Source | Total | Malicious | Suspicious |",
            "|--------|-------|-----------|------------|",
        ]
        for src, stats in summary.source_breakdown.items():
            lines.append(
                f"| {src} | {stats['total']} | {stats['malicious']} | {stats['suspicious']} |"
            )

        # Top 20 high-risk skills
        high_risk = sorted(
            [r for r in results if r.final_verdict in (
                Verdict.MALICIOUS, Verdict.SUSPICIOUS)],
            key=lambda r: (
                0 if r.final_verdict == Verdict.MALICIOUS else 1,
                -(r.stage2.confidence if r.stage2 else 0),
            ),
        )[:20]

        if high_risk:
            lines += [
                "",
                "## Top 20 High-Risk Skills",
                "",
                "| # | Skill ID | Source | Verdict | Confidence | Top Threat |",
                "|---|----------|--------|---------|------------|------------|",
            ]
            for i, r in enumerate(high_risk, 1):
                conf = f"{r.stage2.confidence:.2f}" if r.stage2 else "N/A"
                top_threat = r.stage2.threats[0].category.value if r.stage2 and r.stage2.threats else "-"
                lines.append(
                    f"| {i} | {r.skill.id} | {r.skill.source} | {r.final_verdict.value} | {conf} | {top_threat} |"
                )

        path = self._output_dir / "summary.md"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
