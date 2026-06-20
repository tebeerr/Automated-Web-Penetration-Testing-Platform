from __future__ import annotations

from engine.base_scanner import Finding, Severity
from engine.probes.base import BaseProbe, ProbeContext

REQUIRED_HEADERS: dict[str, tuple[Severity, str]] = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HSTS missing — browsers won't enforce HTTPS for return visits.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "CSP missing — no defense-in-depth against XSS / asset injection.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options missing — MIME sniffing risk.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "X-Frame-Options missing (no frame-ancestors in CSP either) — clickjacking risk.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy missing — referrer URLs may leak to third parties.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Permissions-Policy missing — browser feature scope is fully permissive.",
    ),
}

LEAKY_HEADERS: dict[str, str] = {
    "server": "Server header discloses backend product/version.",
    "x-powered-by": "X-Powered-By discloses backend framework/version.",
    "x-aspnet-version": "X-AspNet-Version discloses .NET version.",
    "x-aspnetmvc-version": "X-AspNetMvc-Version discloses ASP.NET MVC version.",
}


class SecurityHeadersProbe(BaseProbe):
    code = "headers"
    name = "Security Headers Audit"
    owasp_category = "A05"
    owasp_name = "Security Misconfiguration"

    async def run(self, ctx: ProbeContext) -> list[Finding]:
        try:
            resp = await ctx.client.get(ctx.target_url, follow_redirects=True)
        except Exception as e:
            return [
                Finding(
                    name="Unreachable target",
                    description=f"Could not fetch {ctx.target_url}: {e}",
                    severity=Severity.INFO,
                    owasp_category="A05",
                    owasp_name="Security Misconfiguration",
                    url_affected=ctx.target_url,
                    source_scanner="headers",
                )
            ]

        headers_lc = {k.lower(): v for k, v in resp.headers.items()}
        findings: list[Finding] = []

        for header, (sev, message) in REQUIRED_HEADERS.items():
            if header not in headers_lc:
                findings.append(
                    Finding(
                        name=f"Missing header: {header}",
                        description=message,
                        severity=sev,
                        owasp_category=self.owasp_category,
                        owasp_name=self.owasp_name,
                        url_affected=str(resp.url),
                        evidence=f"Response headers do not include {header}.",
                        remediation=f"Send the {header} header on all responses.",
                        source_scanner="headers",
                    )
                )

        for header, message in LEAKY_HEADERS.items():
            if header in headers_lc:
                findings.append(
                    Finding(
                        name=f"Information disclosure: {header}",
                        description=message,
                        severity=Severity.LOW,
                        owasp_category="A05",
                        owasp_name="Security Misconfiguration",
                        url_affected=str(resp.url),
                        evidence=f"{header}: {headers_lc[header]}",
                        remediation=f"Strip the {header} response header at the server/proxy.",
                        source_scanner="headers",
                    )
                )

        return findings
