"""Domain ownership verification: DNS TXT, meta tag, well-known file."""

from __future__ import annotations

import secrets

import aiohttp
import dns.asyncresolver
import dns.exception


def generate_token() -> str:
    return f"sentinel-verify-{secrets.token_hex(16)}"


async def verify_dns(domain: str, expected_token: str) -> bool:
    try:
        answers = await dns.asyncresolver.resolve(domain, "TXT")
    except (dns.exception.DNSException, OSError):
        return False
    for rdata in answers:
        for txt in rdata.strings:
            if txt.decode(errors="ignore").strip() == expected_token:
                return True
    return False


async def verify_meta_tag(domain: str, expected_token: str) -> bool:
    needle = f'<meta name="sentinel-verification" content="{expected_token}">'
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"https://{domain}") as resp:
                html = await resp.text(errors="ignore")
                return needle in html
    except Exception:
        return False


async def verify_file(domain: str, expected_token: str) -> bool:
    url = f"https://{domain}/.well-known/sentinel-verification.txt"
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return False
                content = (await resp.text(errors="ignore")).strip()
                return content == expected_token
    except Exception:
        return False
