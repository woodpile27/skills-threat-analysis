"""Worker configuration loaded from a YAML file."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RabbitMQConfig:
    host: str = "localhost"
    port: int = 5672
    username: str = "guest"
    password: str = "guest"
    vhost: str = "/"
    queue_name: str = "skill.scan.queuebatch"
    prefetch_count: int = 1
    heartbeat: int = 600
    max_retries: int = 3


@dataclass
class MongoConfig:
    uri: str = "mongodb://localhost:27017"
    database: str = "skillscan"
    tasks_collection: str = "tasks"
    reports_collection: str = "reports"


@dataclass
class ScanConfig:
    # "1" rules only; "full" rules then LLM when Stage 1 has findings or TI is not CLEAN;
    # "full-llm" rules then LLM for every skill; "2" always run LLM after rules (worker still runs stage1 first).
    stage: str = "full"
    model: str | None = None
    api_base: str | None = None
    api_key: str | None = None
    api_key_env: str = "ARK_API_KEY"
    batch_size: int = 5
    concurrency: int = 3
    ti_api_key: str | None = None
    enable_qax_ti: bool = False


@dataclass
class WorkerConfig:
    rabbitmq: RabbitMQConfig = field(default_factory=RabbitMQConfig)
    mongodb: MongoConfig = field(default_factory=MongoConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)


def load_config(path: str | Path) -> WorkerConfig:
    """Load worker configuration from a YAML file."""
    raw: dict[str, Any] = {}
    p = Path(path)
    if p.exists():
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    rmq_raw = raw.get("rabbitmq", {})
    mongo_raw = raw.get("mongodb", {})
    scan_raw = raw.get("scan", {})

    return WorkerConfig(
        rabbitmq=RabbitMQConfig(**{k: v for k, v in rmq_raw.items() if k in RabbitMQConfig.__dataclass_fields__}),
        mongodb=MongoConfig(**{k: v for k, v in mongo_raw.items() if k in MongoConfig.__dataclass_fields__}),
        scan=ScanConfig(**{k: v for k, v in scan_raw.items() if k in ScanConfig.__dataclass_fields__}),
    )
