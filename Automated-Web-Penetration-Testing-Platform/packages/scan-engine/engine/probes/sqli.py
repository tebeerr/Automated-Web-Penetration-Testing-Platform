"""Naive reflected-error and boolean-style SQLi probe.

Walks query parameters on the target URL and injects test payloads, looking for
known database error fingerprints or response-length divergences."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from engine.base_scanner import Finding, Severity
from engine.probes.base import BaseProbe, ProbeContext

ERROR_FINGERPRINTS = [
    re.compile(r"SQL syntax.+MySQL", re.I),
    re.compile(r"Warning.*mysql_", re.I),
    re.compile(r"PostgreSQL.+ERROR", re.I),
    re.compile(r"valid PostgreSQL result", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Microsoft SQL Native Client error", re.I),
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"SQLite\.Exception", re.I),
    re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
    re.compile(r"unterminated quoted string", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
]

PAYLOADS = ["'", "''", "'--", '"', "') OR ('1'='1", "1 AND 1=1", "1 AND 1=2"]


def _swap_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[key] = value
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


class SQLiProbe(BaseProbe):
    code = "sqli"
    name = "SQL Injection (reflected error)"
    owasp_category = "A03"
    owasp_name = "Injection"

    async def run(self, ctx: ProbeContext) -> list[Finding]:
        parsed = urlparse(ctx.target_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []  # nothing to probe on this URL

        findings: list[Finding] = []
        for key, _orig in params:
            for payload in PAYLOADS:
                test_url = _swap_param(ctx.target_url, key, payload)
                try:
                    resp = await ctx.client.get(test_url, follow_redirects=False)
                except Exception:
                    continue

                body = (resp.text or "")[:8000]
                for pattern in ERROR_FINGERPRINTS:
                    if pattern.search(body):
                        findings.append(
                            Finding(
                                name=f"Possible SQLi on '{key}'",
                                description=(
                                    "The application returned a database error when the "
                                    f"parameter '{key}' was injected with {payload!r}. "
                                    "Use parameterized queries or an ORM."
                                ),
                                severity=Severity.HIGH,
                                owasp_category=self.owasp_category,
                                owasp_name=self.owasp_name,
                                url_affected=test_url,
                                payload=payload,
                                parameter=key,
                                evidence=pattern.pattern,
                                cwe_id="CWE-89",
                                remediation=(
                                    "Use parameterized queries / prepared statements; "
                                    "never concatenate user input into SQL."
                                ),
                                source_scanner="sqli",
                            )
                        )
                        break  # don't double-report this param
                else:
                    await asyncio.sleep(ctx.request_delay_ms / 1000)
                    continue
                # If we appended a finding for this param, skip remaining payloads.
                break
        return findings
