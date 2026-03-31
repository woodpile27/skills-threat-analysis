"""Extract IOC entities (IP, domain, URL) from text content."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# IPv4 extraction
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"(?<![.\w])"                          # not preceded by dot or word char
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![.\w])"                           # not followed by dot or word char
)

# Patterns that look like version numbers: v1.2.3.4, =1.2.3.4
_VERSION_PREFIX_RE = re.compile(r"[v=]$", re.IGNORECASE)


def _is_public_ipv4(ip_str: str) -> bool:
    """Return True if *ip_str* is a routable, non-reserved public IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return addr.is_global and not addr.is_reserved


def _extract_ipv4(text: str) -> list[tuple[str, int, int]]:
    """Extract public IPv4 addresses, filtering version-number-like patterns.

    Returns list of ``(ip, start, end)`` tuples.
    """
    results: list[tuple[str, int, int]] = []
    for m in _IPV4_RE.finditer(text):
        ip_str = m.group()
        # Skip version-number patterns: preceded by 'v' or '='
        start = m.start()
        if start > 0 and _VERSION_PREFIX_RE.search(text[max(0, start - 1):start]):
            continue
        if _is_public_ipv4(ip_str):
            results.append((ip_str, m.start(), m.end()))
    return results


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"https?://[^\s\"'<>\)\]\}，。、；]+",
    re.IGNORECASE,
)

# Benign host suffixes — URLs matching these are skipped.
_BENIGN_HOST_SUFFIXES = frozenset({
    "github.com",
    "github.io",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "npmjs.org",
    "pypi.org",
    "pypi.python.org",
    "crates.io",
    "rubygems.org",
    "packagist.org",
    "nuget.org",
    "hub.docker.com",
    "registry.npmjs.org",
    "maven.apache.org",
    "repo1.maven.org",
    "registry.yarnpkg.com",
    "golang.org",
    "pkg.go.dev",
    "docs.python.org",
    "developer.mozilla.org",
    "stackoverflow.com",
    "wikipedia.org",
    "wikimedia.org",
    "readthedocs.io",
    "readthedocs.org",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "microsoft.com",
    "azure.com",
    "windows.net",
    "amazonaws.com",
    "aws.amazon.com",
    "cloudflare.com",
    "cloudfront.net",
    "apple.com",
    "anthropic.com",
    "openai.com",
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "schema.org",
    "w3.org",
    "json-schema.org",
    "yaml.org",
    "xml.org",
    "ietf.org",
    "creativecommons.org",
    "opensource.org",
    "spdx.org",
})


def _is_benign_host(host: str) -> bool:
    """Return True if *host* matches a known benign domain."""
    host = host.lower().rstrip(".")
    for suffix in _BENIGN_HOST_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def _extract_urls(text: str) -> list[tuple[str, str, int, int]]:
    """Extract URLs, returning ``(url, host, start, end)`` tuples for non-benign URLs."""
    results: list[tuple[str, str, int, int]] = []
    for m in _URL_RE.finditer(text):
        url = m.group().rstrip(".,;:!?")
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
        except Exception:
            continue
        if not host or _is_benign_host(host):
            continue
        # Skip if host is a private IP
        try:
            if not _is_public_ipv4(host):
                # Could be an IPv4 that's private, or just a hostname
                ipaddress.IPv4Address(host)
                continue  # it's a private/reserved IPv4
        except (ipaddress.AddressValueError, ValueError):
            pass  # not an IPv4 — it's a hostname, which is fine
        results.append((url, host, m.start(), m.start() + len(url)))
    return results


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

# TLDs commonly seen in malicious infrastructure.
_DOMAIN_TLDS = (
    r"com|net|org|io|xyz|top|cc|ru|cn|tk|ml|ga|cf|gq|pw|buzz|club|info|biz|"
    r"online|site|website|space|tech|win|bid|stream|download|racing|review|"
    r"date|loan|men|click|link|work|party|trade|webcam|science|icu|vip|"
    r"pro|mobi|life|live|us|uk|de|fr|jp|kr|br|in|co|me|tv|ly|to|sh|so"
)

_DOMAIN_RE = re.compile(
    r"(?<![/@\w.-])"                       # not preceded by @, /, word, dot, hyphen
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:" + _DOMAIN_TLDS + r")"
    r"(?![.\w])",                           # not followed by dot or word char
    re.IGNORECASE,
)


def _extract_domains(text: str) -> list[tuple[str, int, int]]:
    """Extract standalone domain names (not part of URLs or emails).

    Returns list of ``(domain, start, end)`` tuples.
    """
    results: list[tuple[str, int, int]] = []
    for m in _DOMAIN_RE.finditer(text):
        domain = m.group().lower().rstrip(".")
        # Skip if preceded by :// (would be a URL, already handled)
        start = m.start()
        prefix = text[max(0, start - 3):start]
        if "://" in prefix:
            continue
        if _is_benign_host(domain):
            continue
        results.append((domain, m.start(), m.end()))
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_entities(
    content: str,
    source_file: str = "",
) -> list[tuple[str, str, str, int, int]]:
    """Extract IOC entities from *content*.

    Returns a deduplicated list of ``(kind, value, source_file, start, end)``
    tuples where *kind* is ``"ip"`` or ``"domain_or_url"`` and *start*/*end*
    are character offsets into *content*.
    """
    seen: set[tuple[str, str]] = set()
    results: list[tuple[str, str, str, int, int]] = []

    def _add(kind: str, value: str, start: int, end: int) -> None:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            results.append((kind, value, source_file, start, end))

    # 1. Extract IPs
    for ip, start, end in _extract_ipv4(content):
        _add("ip", ip, start, end)

    # 2. Extract URLs (also collect hosts to avoid duplicate domain extraction)
    url_hosts: set[str] = set()
    for url, host, start, end in _extract_urls(content):
        _add("domain_or_url", url, start, end)
        url_hosts.add(host)

    # 3. Extract standalone domains (skip those already captured via URLs)
    for domain, start, end in _extract_domains(content):
        if domain not in url_hosts:
            _add("domain_or_url", domain, start, end)

    return results


def extract_entities_from_files(
    files: list,
    fallback_content: str = "",
) -> list[tuple[str, str, str, int, int]]:
    """Extract IOC entities from a list of SkillFileSegment objects.

    If *files* is empty, falls back to extracting from *fallback_content*.
    Returns a deduplicated list of ``(kind, value, source_file, start, end)``
    tuples.
    """
    if not files:
        return extract_entities(fallback_content)

    seen: set[tuple[str, str]] = set()
    results: list[tuple[str, str, str, int, int]] = []

    for seg in files:
        for kind, value, src, start, end in extract_entities(seg.content, seg.rel_path):
            key = (kind, value)
            if key not in seen:
                seen.add(key)
                results.append((kind, value, src, start, end))

    return results
