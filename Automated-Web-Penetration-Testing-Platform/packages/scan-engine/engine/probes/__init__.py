from engine.probes.auth import AuthProbe
from engine.probes.base import BaseProbe, ProbeContext
from engine.probes.headers import SecurityHeadersProbe
from engine.probes.sqli import SQLiProbe
from engine.probes.xss import XSSProbe

# NOTE: system-tool probes (nmap_recon, msf_exploit, msf_postexploit) are intentionally
# NOT imported here. They depend on python-nmap / pymetasploit3 which are only present on
# the Kali VM. pipeline_runner imports them directly so web_only scans never require them.

ALL_PROBES: list[type[BaseProbe]] = [
    SecurityHeadersProbe,
    SQLiProbe,
    XSSProbe,
    AuthProbe,
]

__all__ = [
    "ALL_PROBES",
    "AuthProbe",
    "BaseProbe",
    "ProbeContext",
    "SQLiProbe",
    "SecurityHeadersProbe",
    "XSSProbe",
]
