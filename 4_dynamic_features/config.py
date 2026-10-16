from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Settings:
    runtime_seconds: int = 20
    sample_interval_seconds: float = 2.0
    monkey_events: int = 150
    monkey_throttle_ms: int = 100
    install_timeout_seconds: int = 120
    command_timeout_seconds: int = 30
    adaptive_stop: bool = False
    minimum_runtime_seconds: int = 8
    idle_seconds_before_stop: int = 5
    keep_raw: bool = True

    @classmethod
    def load(cls, path: Path | None) -> "Settings":
        data: dict[str, Any] = {}
        if path:
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        allowed = {item.name for item in fields(cls)}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ValueError(f"Unknown config keys: {', '.join(unknown)}")
        return cls(**data)

