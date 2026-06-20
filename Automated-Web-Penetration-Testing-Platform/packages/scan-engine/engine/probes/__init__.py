from engine.probes.auth import AuthProbe
from engine.probes.base import BaseProbe, ProbeContext
from engine.probes.headers import SecurityHeadersProbe
from engine.probes.sqli import SQLiProbe
from engine.probes.xss import XSSProbe

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
