"""QAX Threat Intelligence HTTP client and response formatting.

Extracted from ti_entity_lookup.py for use within the scanner pipeline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
import traceback
from collections import defaultdict
from datetime import datetime
from typing import Any

import requests

logger = logging.getLogger(__name__)

TI_WEBAPI_BASE = "https://webapi.ti.qianxin.com"
TI_V2_BASE = "https://ti.qianxin.com"


def _timestring_to_timestamp(ts: str, fmt: str) -> float:
    dt = datetime.strptime(ts, fmt)
    return time.mktime(dt.timetuple())


class TIFormat:
    max_req_num = 50
    ip_reputation_keys = {
        "geo": ["city", "country", "province", "continent", "isp"],
        "normal_info": ["asn", "asn_org", "owner", "user_type"],
        "whois": ["net_type"],
        "summary_info": ["reputation", "ip"],
    }

    class JudgeType:
        BLACK = "black"
        SUSPICIOUS = "suspicious"
        WHITE = "white"
        UNKNOWN = "unknown"

    @classmethod
    def judge_by_category(cls, items: list) -> str:
        judge = cls.JudgeType.UNKNOWN
        _categories = set()
        for item in items:
            if item.get("ioc_category"):
                _categories.add(item["ioc_category"])
        _black_categories = {"IP_PORT", "DOMAIN_PORT", "TPD"}
        if _black_categories & _categories:
            judge = cls.JudgeType.BLACK
        elif _categories == {"HOST_PORT_URL"}:
            judge = cls.JudgeType.SUSPICIOUS
        return judge

    @classmethod
    def handle_compromise(cls, l: list, judge_by_category: bool = False) -> tuple[dict, str]:
        def handle_tags(record: dict, etime: dict) -> dict:
            result = defaultdict(list)
            for k, v in record.items():
                if not v:
                    continue
                for name, statuses in v.items():
                    if name == "Unknown":
                        continue
                    statuses = list(statuses)
                    t = {"name": name, "status": statuses}
                    _etime = etime.get((k, name))
                    if _etime:
                        t["etime"] = min(_etime)
                    result[k].append(t)
            return dict(result)

        tags = {
            "malicious_family": defaultdict(set),
            "malicious_type": defaultdict(set),
            "tag": defaultdict(set),
            "campaign": defaultdict(set),
        }
        tags_etime = defaultdict(set)

        for i in l:
            etime = i.get("etime")
            if etime:
                etime = _timestring_to_timestamp(etime, "%Y-%m-%dT%H:%M:%S.%fZ")
            current_status = i.get("current_status")
            for k, record in tags.items():
                v = i.get(k)
                if not v:
                    continue
                if isinstance(v, str):
                    tags_etime[(k, v)].add(etime)
                    record[v].add(current_status)
                elif isinstance(v, list):
                    for j in v:
                        tags_etime[(k, j)].add(etime)
                        record[j].add(current_status)

        if judge_by_category:
            risk = cls.judge_by_category(l)
        else:
            risk = "black" if l else "unknown"

        return handle_tags(tags, tags_etime), risk

    @classmethod
    def handle_malicious_info(cls, l: list) -> list:
        names: dict[str, dict] = {}
        for i in l:
            name = i.get("name")
            if not name:
                continue
            ctx = i.get("context") or {}
            names[name] = {
                "name": name,
                "status": [],
                "first_seen": ctx.get("first_seen"),
                "last_seen": ctx.get("last_seen"),
            }
        return list(names.values())

    @classmethod
    def format_ip_reputation(cls, data: dict) -> dict:
        result = {}
        for key, keys in cls.ip_reputation_keys.items():
            result[key] = {k: v for k, v in data.get(key, {}).items() if k in keys}
        tags, risk = cls.handle_compromise(data.get("compromise", []))
        malicious_info = cls.handle_malicious_info(data.get("malicious_info", []))
        reputation = result.get("summary_info", {}).get("reputation")
        if risk == "unknown" and reputation:
            if reputation in ("malicious", "suspicious"):
                risk = "suspicious"
            elif reputation == "benign":
                risk = "white"
        result["risk"] = risk
        if malicious_info:
            tags["malicious_info"] = malicious_info
        if tags:
            tags["src"] = "ti"
            result["tags"] = [tags]
        else:
            result["tags"] = []
        return result


class TiHttpClient:
    """HTTP client for the QAX TI API."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.endpoint: str | None = None
        self.endpointv2: str | None = None
        self.key: str | None = None

    def load_config(self, config: dict[str, str]) -> None:
        self.endpoint = config["endpoint"].rstrip("/")
        self.endpointv2 = config["endpointv2"].rstrip("/")
        self.key = config["key"]

    def prepare_header(self, method: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        if method.lower() == "post":
            headers["Content-Type"] = "application/json"
        return headers

    def close(self) -> None:
        self.session.close()

    def send(
        self,
        method: str,
        url: str,
        params=None,
        body=None,
        headers=None,
        timeout: int = 30,
        retries: int = 3,
        **kwargs,
    ) -> Any:
        method = method.lower()
        if not url.startswith("http"):
            url = f"{self.endpoint}{url}"
        if headers:
            headers = headers.copy()
            headers.update(self.prepare_header(method))
        else:
            headers = self.prepare_header(method)

        while retries:
            try:
                rsp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=body,
                    timeout=timeout,
                    headers=headers,
                    verify=False,
                    **kwargs,
                )
                rsp.raise_for_status()
                ct = rsp.headers.get("Content-Type", "")
                if "application/json" not in ct:
                    return json.loads(rsp.text)
                return rsp.json()
            except (requests.RequestException, ValueError) as e:
                logger.error("request failed %s: %s", url, e)
                logger.debug(traceback.format_exc())
                retries -= 1

        logger.error("exhausted retries for %s", url)
        return None

    def ip_reputations(self, ips: list[str]) -> Any:
        url = f"{self.endpoint}/ip/v3/reputations"
        data = {"params": ips}
        hdr = {"Api-Key": self.key}
        return self.send(method="post", url=url, body=data, headers=hdr)

    def compromise(
        self,
        params: list[str],
        ignore_url: bool = False,
        ignore_port: bool = False,
        ignore_top: bool = False,
    ) -> Any:
        url = f"{self.endpointv2}/api/v2/compromises"
        data = {
            "apikey": self.key,
            "ignore_url": ignore_url,
            "ignore_port": ignore_port,
            "ignore_top": ignore_top,
            "params": params,
        }
        return self.send(method="post", url=url, body=data, headers={"Accept": "application/json"})


def get_ips_reputation(client: TiHttpClient, ips: list[str]) -> dict[str, Any]:
    """Batch IP reputation query. Returns {ip: formatted_result}."""
    results: dict[str, Any] = {}
    n = TIFormat.max_req_num
    for i in range(0, len(ips), n):
        part = ips[i : i + n]
        data = client.ip_reputations(part)
        if data is None:
            continue
        block = data.get("data") or {}
        for k, v in block.items():
            results[k] = TIFormat.format_ip_reputation(v)
    return results


def compromise_and_judge(client: TiHttpClient, params: list[str]) -> dict[str, Any]:
    """Batch domain/URL compromise query. Returns {entity: {tags, risk}}."""
    if not params:
        return {}
    compromise_map: dict[str, Any] = {}
    n = TIFormat.max_req_num
    for i in range(0, len(params), n):
        part = params[i : i + n]
        rsp = client.compromise(part)
        if not rsp or not rsp.get("data"):
            continue
        for k, v in rsp["data"].items():
            if not v:
                continue
            tags: list = []
            ti_tags, risk = TIFormat.handle_compromise(v, judge_by_category=True)
            if ti_tags:
                ti_tags["src"] = "ti"
                tags.append(ti_tags)
            compromise_map[k] = {"tags": tags, "risk": risk}
    return compromise_map


def classify_entity(value: str) -> tuple[str, str]:
    """Classify *value* as ``"ip"`` or ``"domain_or_url"``."""
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip", v
    except ValueError:
        return "domain_or_url", v
