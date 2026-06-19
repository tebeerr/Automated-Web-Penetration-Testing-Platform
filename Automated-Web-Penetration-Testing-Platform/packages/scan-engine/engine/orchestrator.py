from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from engine.base_scanner import BaseScanner, Finding

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int, str], "asyncio.Future | None"]


class ScanOrchestrator:
    """Runs registered scanners in parallel and merges + dedupes findings."""

    def __init__(self, scanners: list[BaseScanner] | None = None, config: dict | None = None):
        self.scanners = scanners or []
        self.config = config or {}
        self._cb: ProgressCallback | None = None

    def register(self, scanner: BaseScanner) -> None:
        self.scanners.append(scanner)

    def on_progress(self, cb: ProgressCallback) -> None:
        self._cb = cb

    async def _notify(self, phase: str, percent: int, message: str = "") -> None:
        if not self._cb:
            return
        result = self._cb(phase, percent, message)
        if asyncio.iscoroutine(result):
            await result

    async def run(self, target_url: str) -> list[Finding]:
        await self._notify("recon", 5, "Checking scanner availability")
        available = [s for s in self.scanners if await s.is_available()]
        if not available:
            raise RuntimeError("No scanners available. Install ZAP/Nuclei/Nmap.")

        total = len(available)
        tasks = [self._run_one(s, target_url, i, total) for i, s in enumerate(available)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        merged: list[Finding] = []
        for r in results:
            if isinstance(r, Exception):
                log.warning("Scanner crashed: %s", r)
                continue
            merged.extend(r)

        await self._notify("scanning", 95, "Deduplicating findings")
        return self._dedupe(merged)

    async def _run_one(
        self, scanner: BaseScanner, target_url: str, index: int, total: int
    ) -> list[Finding]:
        base = 10 + int((index / total) * 70)
        await self._notify("scanning", base, f"Running {scanner.name}")
        return await scanner.scan(target_url, self.config)

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
