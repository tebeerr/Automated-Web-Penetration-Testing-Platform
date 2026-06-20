from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

import httpx

from engine.base_scanner import Finding
from engine.probes.base import BaseProbe, ProbeContext

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int, str], Awaitable[None] | None]


class ScanOrchestrator:
    """Runs registered probes sequentially against a single target URL."""

    def __init__(
        self,
        probes: list[BaseProbe] | None = None,
        user_agent: str = "Sentinel-Scanner/0.1",
        request_delay_ms: int = 200,
        request_timeout_s: float = 15.0,
    ) -> None:
        self.probes: list[BaseProbe] = probes or []
        self.user_agent = user_agent
        self.request_delay_ms = request_delay_ms
        self.request_timeout_s = request_timeout_s
        self._cb: ProgressCallback | None = None

    def register(self, probe: BaseProbe) -> None:
        self.probes.append(probe)

    def on_progress(self, cb: ProgressCallback) -> None:
        self._cb = cb

    async def _notify(self, phase: str, percent: int, message: str = "") -> None:
        if not self._cb:
            return
        result = self._cb(phase, percent, message)
        if asyncio.iscoroutine(result):
            await result

    async def run(self, target_url: str) -> list[Finding]:
        if not self.probes:
            raise RuntimeError("No probes registered.")

        await self._notify("recon", 5, "Preparing HTTP client")
        async with httpx.AsyncClient(
            headers={"User-Agent": self.user_agent},
            timeout=self.request_timeout_s,
            verify=True,
        ) as client:
            ctx = ProbeContext(
                target_url=target_url,
                client=client,
                user_agent=self.user_agent,
                request_delay_ms=self.request_delay_ms,
            )

            all_findings: list[Finding] = []
            total = len(self.probes)
            for index, probe in enumerate(self.probes):
                base = 10 + int((index / total) * 80)
                await self._notify(
                    "scanning",
                    base,
                    f"Running probe {probe.code} ({probe.owasp_category} {probe.owasp_name})",
                )
                try:
                    findings = await probe.run(ctx)
                except Exception as e:
                    log.warning("Probe %s crashed: %s", probe.code, e)
                    findings = []
                all_findings.extend(findings)

            await self._notify("scanning", 95, "Deduplicating findings")
            return self._dedupe(all_findings)

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.name.lower(), f.url_affected, f.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
