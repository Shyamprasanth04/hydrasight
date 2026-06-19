"""IP validation, sanitisation and correction utilities."""
import re
import ipaddress
from typing import Optional


def is_valid_ip(text: str) -> bool:
    """Return True if *text* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(text)
        return True
    except (ValueError, TypeError):
        return False


def dedup_ports(ports: list[dict]) -> list[int]:
    """Return sorted, de-duplicated list of port numbers from port dicts."""
    seen: set[int] = set()
    result: list[int] = []
    for p in ports:
        n = int(p["port"])
        if n not in seen:
            seen.add(n)
            result.append(n)
    return sorted(result)


def force_ip(
    text: str,
    correct: str,
    preserve: Optional[list[str]] = None,
) -> str:
    """
    Replace every IP address in *text* with *correct*,
    except those listed in *preserve* (e.g. lhost, loopback).
    """
    if not text or not is_valid_ip(correct):
        return text
    preserve = preserve or []
    placeholders: dict[str, str] = {}
    for i, ip in enumerate(preserve):
        if is_valid_ip(ip):
            ph = f"__KEEP_IP_{i}__"
            text = text.replace(ip, ph)
            placeholders[ph] = ip
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", correct, text)
    for ph, ip in placeholders.items():
        text = text.replace(ph, ip)
    return text
