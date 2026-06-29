"""
Nmap Reconnaissance Probe
Wraps python-nmap to perform port scanning, service detection,
OS fingerprinting, and NSE vuln script scanning.
"""
import nmap
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from engine.base_scanner import Finding, Severity
from engine.probes.base import BaseProbe, ProbeContext

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredService:
    port: int
    protocol: str       # "tcp" | "udp"
    state: str          # "open" | "filtered" | "closed"
    service: str        # "http", "ssh", "ftp", etc.
    version: str        # "Apache 2.4.41", "OpenSSH 8.2p1"
    product: str
    extra_info: str = ""
    cpe: str = ""


@dataclass
class ReconResult:
    target_ip: str
    hostname: str
    os_matches: list[dict] = field(default_factory=list)
    services: list[DiscoveredService] = field(default_factory=list)
    vuln_scripts: list[dict] = field(default_factory=list)
    raw_xml: str = ""
    scan_duration: float = 0.0


class NmapReconProbe(BaseProbe):
    code = "nmap_recon"
    name = "Nmap Network Reconnaissance"
    owasp_category = "A05"
    owasp_name = "Security Misconfiguration"

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.scan_args = self.config.get(
            "nmap_scan_args", "-sV -sC --top-ports 1000 -T4"
        )
        self.vuln_args = self.config.get("nmap_vuln_args", "--script vuln")
        self.os_detection = self.config.get("nmap_os_detection", False)
        self.timeout = self.config.get("nmap_timeout_seconds", 300)

    def _resolve_target(self, target_url: str) -> str:
        """Extract hostname/IP from URL for Nmap targeting."""
        parsed = urlparse(target_url)
        return parsed.hostname or target_url

    async def run(self, ctx: ProbeContext) -> list[Finding]:
        """
        Execute Nmap scan and convert results to Finding objects.
        Also populates ctx.recon_result for downstream probes.
        """
        target = self._resolve_target(ctx.target_url)
        findings: list[Finding] = []

        try:
            nm = nmap.PortScanner()

            # Phase 1: Service version scan
            logger.info(f"[RECON] Starting Nmap service scan on {target}")
            args = self.scan_args
            if self.os_detection:
                args += " -O"

            # python-nmap runs synchronously — run in executor
            import asyncio
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: nm.scan(target, arguments=args)
            )

            recon = ReconResult(
                target_ip=target,
                hostname=nm[target].hostname() if target in nm.all_hosts() else target,
            )

            # Parse discovered services
            if target in nm.all_hosts():
                host = nm[target]

                # OS detection results
                if "osmatch" in host:
                    recon.os_matches = [
                        {"name": m["name"], "accuracy": m["accuracy"]}
                        for m in host["osmatch"][:3]
                    ]

                # Service enumeration
                for proto in host.all_protocols():
                    for port in host[proto]:
                        svc = host[proto][port]
                        discovered = DiscoveredService(
                            port=port,
                            protocol=proto,
                            state=svc["state"],
                            service=svc.get("name", "unknown"),
                            version=svc.get("version", ""),
                            product=svc.get("product", ""),
                            extra_info=svc.get("extrainfo", ""),
                            cpe=svc.get("cpe", ""),
                        )
                        recon.services.append(discovered)

                        # Generate findings for open ports
                        if svc["state"] == "open":
                            severity = self._rate_service_risk(
                                svc.get("name", ""), port
                            )
                            findings.append(Finding(
                                name=f"Open port {port}/{proto}: {svc.get('name', 'unknown')}",
                                description=(
                                    f"Port {port}/{proto} is open running "
                                    f"{svc.get('product', '')} {svc.get('version', '')}. "
                                    f"Service: {svc.get('name', 'unknown')}."
                                ),
                                severity=severity,
                                owasp_category=self.owasp_category,
                                owasp_name=self.owasp_name,
                                url_affected=f"{ctx.target_url}:{port}",
                                source_scanner="nmap",
                                evidence=f"nmap {args} {target}",
                            ))

            # Phase 2: Vulnerability script scan
            logger.info(f"[RECON] Running Nmap vuln scripts on {target}")
            nm_vuln = nmap.PortScanner()
            await loop.run_in_executor(
                None, lambda: nm_vuln.scan(target, arguments=self.vuln_args)
            )

            if target in nm_vuln.all_hosts():
                host_vuln = nm_vuln[target]
                for proto in host_vuln.all_protocols():
                    for port in host_vuln[proto]:
                        svc = host_vuln[proto][port]
                        if "script" in svc:
                            for script_name, output in svc["script"].items():
                                if self._is_vuln_positive(output):
                                    recon.vuln_scripts.append({
                                        "port": port,
                                        "script": script_name,
                                        "output": output[:500],
                                    })
                                    findings.append(Finding(
                                        name=f"NSE vuln: {script_name} (port {port})",
                                        description=output[:300],
                                        severity=Severity.HIGH,
                                        owasp_category=self.owasp_category,
                                        owasp_name=self.owasp_name,
                                        url_affected=f"{ctx.target_url}:{port}",
                                        source_scanner="nmap-nse",
                                        evidence=f"nmap {self.vuln_args} {target}",
                                    ))

            # Store recon result on context for downstream probes
            ctx.recon_result = recon

        except nmap.PortScannerError as e:
            logger.error(f"[RECON] Nmap scan failed: {e}")
            findings.append(Finding(
                name="Nmap scan error",
                description=f"Reconnaissance scan failed: {str(e)}",
                severity=Severity.INFO,
                owasp_category=self.owasp_category,
                owasp_name=self.owasp_name,
                url_affected=ctx.target_url,
                source_scanner="nmap",
            ))

        return findings

    def _rate_service_risk(self, service_name: str, port: int) -> Severity:
        """Assign severity based on exposed service type."""
        high_risk = {"ftp", "telnet", "mysql", "mssql", "rdp", "vnc", "smb"}
        medium_risk = {"ssh", "smtp", "snmp", "pop3", "imap"}

        if service_name.lower() in high_risk:
            return Severity.HIGH
        if service_name.lower() in medium_risk:
            return Severity.MEDIUM
        return Severity.LOW

    def _is_vuln_positive(self, script_output: str) -> bool:
        """Check if NSE script output indicates a confirmed vulnerability."""
        positive_indicators = [
            "VULNERABLE", "vulnerable", "State: VULNERABLE",
            "LIKELY VULNERABLE", "NOT safe",
        ]
        negative_indicators = [
            "NOT VULNERABLE", "Could not", "ERROR",
            "false positive", "not vulnerable",
        ]
        output_lower = script_output.lower()
        if any(neg.lower() in output_lower for neg in negative_indicators):
            return False
        return any(pos.lower() in output_lower for pos in positive_indicators)