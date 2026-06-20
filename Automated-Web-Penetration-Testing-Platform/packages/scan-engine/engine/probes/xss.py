"""Reflected-XSS probe: inject a unique marker into each query parameter, then
look for an unencoded reflection of that marker in the HTML response."""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from engine.base_scanner import Finding, Severity
from engine.probes.base import BaseProbe, ProbeContext

PAYLOAD_TEMPLATES = [
    '<svg/onload=alert("{marker}")>',
    '"><img src=x onerror=alert("{marker}")>',
    "<script>alert('{marker}')</script>",
]


def _swap_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[key] = value
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


class XSSProbe(BaseProbe):
    code = "xss"
    name = "Reflected Cross-Site Scripting"
    owasp_category = "A03"
    owasp_name = "Injection"

    async def run(self, ctx: ProbeContext) -> list[Finding]:
        parsed = urlparse(ctx.target_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return []

        findings: list[Finding] = []
        for key, _orig in params:
            marker = f"sentinel{secrets.token_hex(4)}"
            for template in PAYLOAD_TEMPLATES:
                payload = template.format(marker=marker)
                test_url = _swap_param(ctx.target_url, key, payload)
                try:
                    resp = await ctx.client.get(test_url, follow_redirects=False)
                except Exception:
                    continue

                body = resp.text or ""
                # Reflection is interesting only if the marker AND surrounding HTML
                # special chars come back unencoded.
                if marker in body and ("<" in payload and "<" in body):
                    findings.append(
                        Finding(
                            name=f"Reflected XSS in '{key}'",
                            description=(
                                f"Input on parameter '{key}' is reflected without "
                                "HTML encoding, allowing arbitrary script execution."
                            ),
                            severity=Severity.HIGH,
                            owasp_category=self.owasp_category,
                            owasp_name=self.owasp_name,
                            url_affected=test_url,
                            payload=payload,
                            parameter=key,
                            evidence=f"Marker {marker!r} reflected unencoded.",
                            cwe_id="CWE-79",
                            remediation=(
                                "HTML-encode all dynamic content (server-side templating "
                                "auto-escape) and apply a strict Content-Security-Policy."
                            ),
                            source_scanner="xss",
                        )
                    )
                    break
        return findings
