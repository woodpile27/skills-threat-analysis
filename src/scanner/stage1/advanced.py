"""Advanced detection passes ported from skill-scan-1.0.0 prompt_analyzer.

Implements six code-level checks that cannot be expressed as pure regex rules:

* PA-001  Invisible Unicode density analysis
* PA-002  Homoglyph (confusable) attack detection
* PA-003  Mixed-script anomaly detection
* PA-004  Markdown hidden-instruction extraction
* PA-005  Gradual escalation structure analysis
* PA-006  Encoded payload detection (Base64 / ROT13)
"""

from __future__ import annotations

import base64
import re

from scanner.models import RuleMatch, Severity

# ---------------------------------------------------------------------------
# Data tables (ported from skill-scan-1.0.0 prompt_analyzer.py)
# ---------------------------------------------------------------------------

INVISIBLE_CHARS: list[str] = [
    "\u200B",  # Zero-width space
    "\u200C",  # Zero-width non-joiner
    "\u200D",  # Zero-width joiner
    "\uFEFF",  # Byte order mark
    "\u00AD",  # Soft hyphen
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\u180E",  # Mongolian vowel separator
    "\u200E",  # Left-to-right mark
    "\u200F",  # Right-to-left mark
    "\u202A",  # Left-to-right embedding
    "\u202B",  # Right-to-left embedding
    "\u202C",  # Pop directional formatting
    "\u202D",  # Left-to-right override
    "\u202E",  # Right-to-left override
    "\u2066",  # Left-to-right isolate
    "\u2067",  # Right-to-left isolate
    "\u2068",  # First strong isolate
    "\u2069",  # Pop directional isolate
]

# Cyrillic / Greek characters that are visually identical to Latin letters.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0410": "A", "\u0412": "B", "\u0415": "E",
    "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0423": "Y", "\u0425": "X",
    # Greek
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b7": "n", "\u03b9": "i",
    "\u03ba": "k", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t",
    "\u03c5": "u", "\u03c7": "x",
}

SCRIPT_RANGES: dict[str, re.Pattern[str]] = {
    "latin":      re.compile(r"[\u0041-\u024F]"),
    "cyrillic":   re.compile(r"[\u0400-\u04FF]"),
    "greek":      re.compile(r"[\u0370-\u03FF]"),
    "arabic":     re.compile(r"[\u0600-\u06FF]"),
    "cjk":        re.compile(r"[\u4E00-\u9FFF\u3400-\u4DBF]"),
    "hangul":     re.compile(r"[\uAC00-\uD7AF]"),
    "devanagari": re.compile(r"[\u0900-\u097F]"),
}

# ROT13-encoded forms of suspicious injection keywords.
ROT13_INJECTIONS: dict[str, str] = {
    "vtaber": "ignore",
    "flfgrz": "system",
    "bireevqr": "override",
    "vafgehpgvbaf": "instructions",
    "riny": "eval",
    "rkrp": "exec",
}

# Emoji range – used to skip ZWJ (U+200D) inside emoji sequences.
_EMOJI_RANGE_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F900-\U0001F9FF]"
)

# Arabic/Persian script range – used to skip ZWNJ (U+200C) that is grammatically
# required as a syllable connector in Farsi/Persian and other Arabic-script languages.
_ARABIC_RANGE_RE = re.compile(r"[\u0600-\u06FF]")

# Regex for extracting Base64-like blocks (≥40 chars).
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_ROT13_TOKEN_RE = re.compile(r"\b[A-Za-z]{4,}\b")
_ROT13_CODE_SIGNAL_RE = re.compile(r"\b(?:eval|exec|system)\s*\(", re.IGNORECASE)
_SIGNATURE_FIELD_RE = re.compile(
    r'["\']?[\w.-]*(?:signature|checksum|digest|hash)[\w.-]*["\']?\s*:',
    re.IGNORECASE,
)

# Markdown patterns for hidden-content extraction.
_MD_IMG_ALT_RE  = re.compile(r"!\[([^\]]{20,})\]\(")
_MD_COMMENT_RE  = re.compile(r"<!--([\s\S]*?)-->")
_MD_LINK_RE     = re.compile(r"\[([^\]]{20,})\]\([^)]+\)")
# Tightened: require MIME type format (contains "/") to avoid matching TypeScript
# type annotations like (data: DashboardData) or (data: unknown).
_MD_DATA_URI_RE = re.compile(r"\(data:[a-zA-Z]+/[^)]+\)")

# Instruction-signal phrases used by _looks_like_instruction().
# NOTE: Only include phrases strongly indicative of prompt injection.
# Common skill phrases like "you must", "execute", "important:" cause
# massive false positives in PA-005 gradual escalation detection.
_INSTRUCTION_SIGNALS: list[str] = [
    # Instruction override / hijacking signals
    "ignore all", "ignore previous", "ignore prior", "ignore system",
    "disregard", "override system", "override safety",
    "forget everything", "forget your",
    # Secrecy / suppression signals
    "do not tell", "don't tell", "never tell", "never mention",
    "do not reveal", "don't reveal", "never reveal",
    # Prompt / instruction manipulation
    "new instructions", "real instructions", "actual instructions",
    "system prompt", "hidden instruction",
    # Role hijacking
    "you are now DAN", "you are now STAN", "jailbreak",
    "pretend you are", "pretend to be",
    "admin mode", "debug mode", "developer mode", "god mode",
    # Data exfiltration signals
    "send all", "share your", "exfiltrate", "leak",
]


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class AdvancedAnalyzer:
    """Code-level detection passes that complement the regex rule engine."""

    @staticmethod
    def _is_gitcrypt_blob(content: str) -> bool:
        """Return True if *content* is a git-crypt encrypted binary blob.

        git-crypt blobs begin with the 10-byte magic ``\\x00GITCRYPT\\x00``.
        When a repo uses git-crypt and the file is not decrypted the loader
        still reads the raw bytes as a string, making the content unparseable
        text. All advanced Unicode/script checks would produce false positives
        on such binary data, so callers should skip them entirely.
        """
        return content.startswith("\x00GITCRYPT")

    def scan(
        self,
        content: str,
        masked_ranges: list[tuple[int, int]],
    ) -> list[RuleMatch]:
        """Run all advanced passes and return :class:`RuleMatch` objects."""
        matches: list[RuleMatch] = []
        matches.extend(self._detect_invisible_unicode(content))
        matches.extend(self._detect_mixed_scripts(content))
        matches.extend(self._detect_markdown_injection(content, masked_ranges))
        matches.extend(self._detect_gradual_escalation(content))
        matches.extend(self._detect_encoded_payloads(content))
        return matches

    # -- PA-001: Invisible Unicode density ------------------------------------

    @staticmethod
    def _detect_invisible_unicode(content: str) -> list[RuleMatch]:
        findings: list[RuleMatch] = []
        count = 0
        first_pos = -1

        for char in INVISIBLE_CHARS:
            idx = content.find(char)
            while idx != -1:
                # Skip U+200D when it's part of an emoji ZWJ sequence.
                if char == "\u200D":
                    before = content[idx - 1] if idx > 0 else ""
                    after = content[idx + 1] if idx + 1 < len(content) else ""
                    if _EMOJI_RANGE_RE.match(before) or _EMOJI_RANGE_RE.match(after):
                        idx = content.find(char, idx + 1)
                        continue

                # Skip U+200C (ZWNJ) when adjacent to Arabic/Persian script characters
                # (U+0600–U+06FF). ZWNJ is a grammatically required connector in Farsi/Persian
                # and its presence in i18n files is entirely legitimate.
                if char == "\u200C":
                    before = content[idx - 1] if idx > 0 else ""
                    after = content[idx + 1] if idx + 1 < len(content) else ""
                    if _ARABIC_RANGE_RE.match(before) or _ARABIC_RANGE_RE.match(after):
                        idx = content.find(char, idx + 1)
                        continue

                if first_pos == -1:
                    first_pos = idx
                count += 1
                idx = content.find(char, idx + 1)

        # Require at least 3 invisible chars before reporting. 1–2 occurrences are
        # common copy-paste artifacts from Google Translate / Google Docs exports and
        # do not constitute a credible steganographic threat.
        if count < 3:
            return findings

        # Density alone is insufficient to determine intent: 212 chars may be a
        # creator watermark, 6 chars may be a copy-paste U+200B artifact from
        # web-scraped documentation. Escalating to HIGH/CRITICAL based purely on
        # count produced a very high false-positive rate. Confirmed hidden injection
        # is already covered by the strip-and-rescan pass below (CRITICAL).
        severity = Severity.MEDIUM

        findings.append(RuleMatch(
            rule_id="PA-001",
            rule_name="invisible_unicode_density",
            severity=severity,
            matched_text=f"{count} invisible Unicode char(s)",
            position=(first_pos, first_pos + 1),
            pattern="(advanced) invisible char density",
        ))

        # Strip-and-rescan: if many invisible chars, check whether the cleaned
        # text reveals injection keywords that were hidden between visible text.
        # Only fire when the keyword is genuinely revealed by stripping — i.e. it
        # was NOT already present in the original (visible) content. If the keyword
        # was already visible, stripping didn't uncover anything hidden; this
        # prevents false positives on skills whose documentation legitimately
        # mentions terms like "system prompt" in an educational context.
        if count > 5:
            char_set = set(INVISIBLE_CHARS)
            stripped = "".join(ch for ch in content if ch not in char_set)
            if _looks_like_instruction(stripped) and not _looks_like_instruction(content):
                findings.append(RuleMatch(
                    rule_id="PA-001",
                    rule_name="invisible_unicode_hidden_injection",
                    severity=Severity.CRITICAL,
                    matched_text="Injection keywords revealed after stripping invisible chars",
                    position=(first_pos, first_pos + 1),
                    pattern="(advanced) strip-and-rescan",
                ))

        return findings

    # PA-002 (homoglyph_attack) was removed.
    #
    # Rationale: the detection matched any Cyrillic character that visually
    # resembles a Latin letter (а→a, е→e, о→o, …). This fired HIGH on every
    # skill that contains even a single legitimate Cyrillic word inside an
    # otherwise Latin-dominant document (i18n tables, API reference docs,
    # language-support matrices, etc.), producing a very high false-positive
    # rate with no practical way to distinguish real homoglyph substitution
    # attacks from normal multilingual content.
    #
    # A true homoglyph attack embeds Cyrillic *within* a Latin keyword (e.g.
    # "ignоre" with Cyrillic о), which requires a completely different detection
    # strategy (intra-word character boundary analysis) not implemented here.
    # The mixed-script ratio check in PA-003 already covers balanced-proportion
    # Latin/Cyrillic blends that are the primary obfuscation vector.

    # -- PA-003: Mixed-script anomaly -----------------------------------------

    @staticmethod
    def _detect_mixed_scripts(content: str) -> list[RuleMatch]:
        # git-crypt encrypted blobs are binary; skip to avoid false positives.
        if AdvancedAnalyzer._is_gitcrypt_blob(content):
            return []

        detected: dict[str, int] = {}
        for name, regex in SCRIPT_RANGES.items():
            n = len(regex.findall(content))
            if n:
                detected[name] = n

        findings: list[RuleMatch] = []

        # Latin + Cyrillic mix detection — ratio-based to avoid false positives on
        # Russian/Bulgarian skill descriptions that naturally contain Latin technical
        # terms (product names, API names, URLs) alongside Cyrillic body text.
        #
        # A real mixed-script homoglyph/obfuscation attack uses BOTH scripts in
        # roughly balanced proportions. Legitimate Russian text is overwhelmingly
        # Cyrillic with only a small fraction of Latin (technical terms), giving a
        # minority ratio well below 20%.
        latin = detected.get("latin", 0)
        cyrillic = detected.get("cyrillic", 0)
        if latin > 0 and cyrillic > 0:
            total = latin + cyrillic
            minority_ratio = min(latin, cyrillic) / total
            if minority_ratio > 0.20:
                findings.append(RuleMatch(
                    rule_id="PA-003",
                    rule_name="mixed_scripts_latin_cyrillic",
                    severity=Severity.HIGH,
                    matched_text=(
                        f"Latin ({latin} chars) + "
                        f"Cyrillic ({cyrillic} chars) "
                        f"[minority ratio {minority_ratio:.0%}]"
                    ),
                    position=(0, 1),
                    pattern="(advanced) mixed scripts",
                ))

        # More than 4 distinct scripts is unusual. Threshold raised from 3 to 4
        # to avoid false positives on legitimate i18n JS bundles that support
        # Arabic, CJK, and Hangul alongside Latin/Cyrillic for error messages.
        if len(detected) > 4:
            scripts = ", ".join(detected.keys())
            findings.append(RuleMatch(
                rule_id="PA-003",
                rule_name="mixed_scripts_multi",
                severity=Severity.MEDIUM,
                matched_text=f"{len(detected)} scripts: {scripts}",
                position=(0, 1),
                pattern="(advanced) mixed scripts",
            ))

        return findings

    # -- PA-004: Markdown hidden instructions ---------------------------------

    @staticmethod
    def _detect_markdown_injection(
        content: str,
        masked_ranges: list[tuple[int, int]],
    ) -> list[RuleMatch]:
        findings: list[RuleMatch] = []

        def _in_mask(start: int, end: int) -> bool:
            for rs, re_ in masked_ranges:
                if start >= rs and end <= re_:
                    return True
            return False

        # Image alt-text with instruction-like content.
        for m in _MD_IMG_ALT_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            alt_text = m.group(1)
            if _looks_like_instruction(alt_text):
                findings.append(RuleMatch(
                    rule_id="PA-004",
                    rule_name="markdown_hidden_instruction",
                    severity=Severity.HIGH,
                    matched_text=f"img alt: {alt_text[:80]}",
                    position=(m.start(), m.end()),
                    pattern="(advanced) markdown injection",
                ))

        # HTML comments containing instruction-like content.
        for m in _MD_COMMENT_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            comment = m.group(1).strip()
            if _looks_like_instruction(comment):
                findings.append(RuleMatch(
                    rule_id="PA-004",
                    rule_name="markdown_hidden_instruction",
                    severity=Severity.HIGH,
                    matched_text=f"comment: {comment[:80]}",
                    position=(m.start(), m.end()),
                    pattern="(advanced) markdown injection",
                ))

        # Link text with instruction-like content.
        for m in _MD_LINK_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            link_text = m.group(1)
            if _looks_like_instruction(link_text):
                findings.append(RuleMatch(
                    rule_id="PA-004",
                    rule_name="markdown_hidden_instruction",
                    severity=Severity.HIGH,
                    matched_text=f"link: {link_text[:80]}",
                    position=(m.start(), m.end()),
                    pattern="(advanced) markdown injection",
                ))

        # Data URIs embedded in markdown.
        for m in _MD_DATA_URI_RE.finditer(content):
            if _in_mask(m.start(), m.end()):
                continue
            findings.append(RuleMatch(
                rule_id="PA-004",
                rule_name="markdown_data_uri",
                severity=Severity.MEDIUM,
                matched_text=m.group(0)[:80],
                position=(m.start(), m.end()),
                pattern="(advanced) markdown data URI",
            ))

        return findings

    # -- PA-005: Gradual escalation -------------------------------------------

    @staticmethod
    def _detect_gradual_escalation(content: str) -> list[RuleMatch]:
        paragraphs = re.split(r"\n\s*\n", content)
        if len(paragraphs) < 5:
            return []

        has_early_innocent = False
        late_aggressive_count = 0

        for i, para in enumerate(paragraphs):
            position = i / len(paragraphs)
            is_instr = _looks_like_instruction(para)

            if position < 0.3 and not is_instr:
                has_early_innocent = True
            if position > 0.7 and is_instr:
                late_aggressive_count += 1

        if has_early_innocent and late_aggressive_count >= 5:
            return [RuleMatch(
                rule_id="PA-005",
                rule_name="gradual_escalation",
                severity=Severity.MEDIUM,
                matched_text="Early innocent content followed by late instruction-like content",
                position=(0, 1),
                pattern="(advanced) gradual escalation",
            )]

        return []

    # -- PA-006: Encoded payloads (Base64 / ROT13) ----------------------------

    @staticmethod
    def _detect_encoded_payloads(content: str) -> list[RuleMatch]:
        findings: list[RuleMatch] = []
        base64_ranges = [(m.start(), m.end()) for m in _BASE64_RE.finditer(content)]

        # Base64 blocks.
        for start, end in base64_ranges:
            try:
                decoded = base64.b64decode(content[start:end]).decode("utf-8", errors="replace")
                printable = "".join(c for c in decoded if 32 <= ord(c) <= 126 or c == "\n")
                if len(printable) > len(decoded) * 0.7 and _looks_like_instruction(decoded):
                    findings.append(RuleMatch(
                        rule_id="PA-006",
                        rule_name="encoded_payload_base64",
                        severity=Severity.HIGH,
                        matched_text=f"Base64 decodes to: {printable[:80]}",
                        position=(start, end),
                        pattern="(advanced) base64 decode",
                    ))
            except Exception:
                pass

        # ROT13-encoded injection terms.
        for line_start, line in _iter_lines(content):
            if _looks_like_signature_blob_line(line):
                continue

            line_matches: list[tuple[str, str, int, int]] = []
            for match in _ROT13_TOKEN_RE.finditer(line):
                encoded = match.group(0).lower()
                decoded = ROT13_INJECTIONS.get(encoded)
                if decoded is None:
                    continue

                start = line_start + match.start()
                end = line_start + match.end()
                if _is_in_ranges(start, end, base64_ranges):
                    continue

                line_matches.append((encoded, decoded, start, end))

            if not line_matches:
                continue

            decoded_line = _rot13(line)
            if len(line_matches) < 2 and not (
                _looks_like_instruction(decoded_line)
                or _ROT13_CODE_SIGNAL_RE.search(decoded_line)
            ):
                continue

            for encoded, decoded, start, end in line_matches:
                findings.append(RuleMatch(
                    rule_id="PA-006",
                    rule_name="encoded_payload_rot13",
                    severity=Severity.MEDIUM,
                    matched_text=f'ROT13 "{encoded}" -> "{decoded}"',
                    position=(start, end),
                    pattern="(advanced) ROT13 lookup",
                ))

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _looks_like_instruction(text: str) -> bool:
    """Return True if *text* contains instruction-like signal phrases."""
    if not text or len(text) < 10:
        return False
    lower = text.lower()
    return any(signal in lower for signal in _INSTRUCTION_SIGNALS)


def _iter_lines(text: str) -> list[tuple[int, str]]:
    """Return lines with their starting offsets."""
    lines: list[tuple[int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        lines.append((offset, line))
        offset += len(line)
    if text and not lines:
        lines.append((0, text))
    return lines


def _is_in_ranges(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    """Return True when [start, end) lies entirely within one of *ranges*."""
    for range_start, range_end in ranges:
        if start >= range_start and end <= range_end:
            return True
    return False


def _looks_like_signature_blob_line(line: str) -> bool:
    """Return True for metadata lines that carry long signature/hash-like blobs."""
    return _SIGNATURE_FIELD_RE.search(line) is not None and _BASE64_RE.search(line) is not None


def _rot13(s: str) -> str:
    """Decode a ROT13-encoded string."""
    result: list[str] = []
    for c in s:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)
