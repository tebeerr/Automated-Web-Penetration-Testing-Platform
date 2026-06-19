"""Renders a security report HTML via Jinja2 then converts to PDF via WeasyPrint."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


class PDFReportBuilder:
    def __init__(self, template_dir: str | None = None) -> None:
        base = Path(template_dir) if template_dir else Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(base)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def generate(
        self,
        scan: Any,
        findings: list[Any],
        summary: str,
        stats: dict[str, int],
        output_dir: str | None = None,
    ) -> str:
        # WeasyPrint runs synchronously; we keep the signature async so the worker
        # can offload to a thread pool if needed.
        from weasyprint import HTML  # local import keeps base install light

        template = self.env.get_template("report_base.html")

        by_owasp: dict[str, list[Any]] = {}
        for f in findings:
            if getattr(f, "is_false_positive", False):
                continue
            by_owasp.setdefault(f.owasp_category, []).append(f)

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for cat in by_owasp:
            by_owasp[cat].sort(
                key=lambda f: sev_rank.get(getattr(f.severity, "value", "info"), 5)
            )

        html_content = template.render(
            scan=scan,
            findings_by_owasp=by_owasp,
            executive_summary=summary,
            stats=stats,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        out_dir = output_dir or os.environ.get("REPORTS_DIR", "/app/reports")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"sentinel_report_{scan.id}.pdf")
        HTML(string=html_content).write_pdf(out_path)
        return out_path
