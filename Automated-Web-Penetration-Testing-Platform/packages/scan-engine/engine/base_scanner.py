from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Universal vulnerability finding produced by every scanner."""

    name: str
    description: str
    severity: Severity
    owasp_category: str  # A01..A10
    owasp_name: str
    url_affected: str
    evidence: str = ""
    payload: str = ""
    parameter: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    remediation: str = ""
    source_scanner: str = ""
    ai_confidence: float = 1.0
    ai_narrative: str = ""
    is_false_positive: bool = False
    raw_output: dict[str, Any] = field(default_factory=dict)


class BaseScanner(ABC):
    name: str = "base"

    @abstractmethod
    async def scan(self, target_url: str, config: dict | None = None) -> list[Finding]:
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        ...
