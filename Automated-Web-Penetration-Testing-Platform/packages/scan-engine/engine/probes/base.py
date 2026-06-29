from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from engine.base_scanner import Finding


@dataclass
class ProbeContext:
    """Shared state passed to every probe in a scan."""

    target_url: str
    # httpx client for web-layer probes; None for system-tool probes (nmap/msf).
    client: httpx.AsyncClient | None = None
    user_agent: str = "Sentinel-Scanner/0.1"
    request_delay_ms: int = 200
    metadata: dict[str, Any] | None = None
    # Populated by NmapReconProbe; consumed by the Metasploit probes downstream.
    recon_result: Any | None = None


class BaseProbe(ABC):
    """Each probe inspects one OWASP category and returns findings."""

    code: str = "A00"
    name: str = "base"
    owasp_category: str = "A00"
    owasp_name: str = "Base"

    @abstractmethod
    async def run(self, ctx: ProbeContext) -> list[Finding]:
        ...
