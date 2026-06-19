"""Chains FP filter → severity ranker → remediation writer → exec summary.

This is the integration surface. Each individual agent class will live under
agent/agents/ and be wired into `analyze()` as it lands.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from agent.providers.base import LLMProvider


class AIOrchestrator:
    def __init__(self, llm: LLMProvider) -> None:
        self.llm = llm
        self._cb: Callable[[str, int, str], Any] | None = None

    def on_progress(self, cb: Callable[[str, int, str], Any]) -> None:
        self._cb = cb

    async def _notify(self, percent: int, message: str) -> None:
        if not self._cb:
            return
        out = self._cb("ai_analyzing", percent, message)
        if asyncio.iscoroutine(out):
            await out

    async def analyze(self, findings: list[Any], target_url: str) -> dict[str, Any]:
        # Stub pipeline. Replace each step with the real agent class.
        await self._notify(10, "Filtering false positives")
        await self._notify(35, "Re-evaluating severity")
        await self._notify(60, "Writing remediation guidance")
        await self._notify(85, "Drafting executive summary")
        await self._notify(100, "AI analysis complete")

        stats = _aggregate(findings)
        return {
            "findings": findings,
            "executive_summary": "",
            "stats": stats,
        }


def _aggregate(findings: list[Any]) -> dict[str, int]:
    counts = {"total": len(findings), "real": 0, "false_positives": 0,
              "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if getattr(f, "is_false_positive", False):
            counts["false_positives"] += 1
            continue
        counts["real"] += 1
        sev = getattr(getattr(f, "severity", None), "value", None) or "info"
        if sev in counts:
            counts[sev] += 1
    return counts
