"""Lightweight authentication-surface probe.

Checks for:
- login/auth endpoints reachable over plain HTTP (mixed content / credential leak risk)
- common authentication endpoints that respond without rate limiting hints
- cookies set without Secure / HttpOnly flags
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from engine.base_scanner import Finding, Severity
from engine.probes.base import BaseProbe, ProbeContext

AUTH_PATHS = ("/login", "/signin", "/auth", "/account/login")


class AuthProbe(BaseProbe):
    code = "auth"
    name = "Authentication Hygiene"
    owasp_category = "A07"
    owasp_name = "Identification and Authentication Failures"

    async def run(self, ctx: ProbeContext) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(ctx.target_url)
        base_origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        # 1. Plaintext HTTP login surface.
        if parsed.scheme == "http":
            findings.append(
                Finding(
                    name="Login surface reachable over plain HTTP",
                    description=(
                        "Credentials submitted on a plain-HTTP origin are visible to "
                        "any on-path attacker."
                    ),
                    severity=Severity.HIGH,
                    owasp_category="A02",
                    owasp_name="Cryptographic Failures",
                    url_affected=ctx.target_url,
                    remediation="Force HTTPS site-wide and serve HSTS.",
                    source_scanner="auth",
                )
            )

        # 2. Cookie flags on the entry page.
        try:
            resp = await ctx.client.get(ctx.target_url, follow_redirects=True)
        except Exception:
            resp = None

        if resp is not None:
            for raw_cookie in resp.headers.get_list("set-cookie") if hasattr(
                resp.headers, "get_list"
            ) else resp.headers.get_all("set-cookie") if hasattr(
                resp.headers, "get_all"
            ) else _multi_header(resp.headers, "set-cookie"):
                low = raw_cookie.lower()
                name = raw_cookie.split("=", 1)[0]
                missing = []
                if "secure" not in low:
                    missing.append("Secure")
                if "httponly" not in low:
                    missing.append("HttpOnly")
                if missing:
                    findings.append(
                        Finding(
                            name=f"Insecure cookie flags on '{name}'",
                            description=f"Cookie '{name}' missing: {', '.join(missing)}.",
                            severity=Severity.MEDIUM,
                            owasp_category=self.owasp_category,
                            owasp_name=self.owasp_name,
                            url_affected=str(resp.url),
                            evidence=raw_cookie,
                            remediation="Add Secure, HttpOnly, and SameSite=Lax (or Strict).",
                            source_scanner="auth",
                        )
                    )

        # 3. Probe known auth paths for 200 responses without lockout signal.
        for path in AUTH_PATHS:
            url = base_origin + path
            try:
                probe_resp = await ctx.client.get(url, follow_redirects=False)
            except Exception:
                continue
            if probe_resp.status_code in (200, 301, 302, 303, 307, 308):
                findings.append(
                    Finding(
                        name=f"Auth endpoint reachable: {path}",
                        description=(
                            f"{url} is reachable (status {probe_resp.status_code}). "
                            "Verify it enforces rate limiting and account lockout."
                        ),
                        severity=Severity.INFO,
                        owasp_category=self.owasp_category,
                        owasp_name=self.owasp_name,
                        url_affected=url,
                        evidence=f"HTTP {probe_resp.status_code}",
                        remediation=(
                            "Apply rate limiting, account lockout, and bot mitigation on "
                            "authentication endpoints."
                        ),
                        source_scanner="auth",
                    )
                )
        return findings


def _multi_header(headers, name: str) -> list[str]:
    return [v for k, v in headers.items() if k.lower() == name.lower()]
