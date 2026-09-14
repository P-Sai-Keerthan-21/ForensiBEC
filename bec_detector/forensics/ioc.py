"""Indicator-of-compromise extraction and normalisation.

IOCs are pulled only from what was actually parsed out of the evidence: header
addresses, the Received chain, body URLs and attachment hashes. Nothing here is
looked up externally.

Normalisation rules (so the same indicator from two cases compares equal):
  * addresses and domains -> lower-case, surrounding punctuation stripped
  * URLs                  -> scheme and host lower-cased, fragment dropped
  * hashes                -> lower-case hex
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from ..models import EmailArtifact

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Private / loopback / link-local ranges carry no intelligence value.
PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "0.", "255.")


def _is_routable(ip: str) -> bool:
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    try:
        values = [int(o) for o in octets]
    except ValueError:
        return False
    if any(v > 255 for v in values):
        return False
    if ip.startswith(PRIVATE_PREFIXES):
        return False
    if values[0] == 172 and 16 <= values[1] <= 31:
        return False
    return True


def normalise_url(raw: str) -> str:
    try:
        parts = urlsplit(raw)
        return urlunsplit((
            parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""
        ))
    except Exception:
        return raw.strip()


def normalise_domain(raw: str) -> str:
    return raw.strip().strip(".").lower()


def extract_iocs(email: EmailArtifact) -> dict[str, list[str]]:
    """Collect and normalise every indicator observable in one message."""
    addresses: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()
    ips: set[str] = set()
    hashes: set[str] = set()

    # -- header addresses ---------------------------------------------------
    for value in (email.from_address, email.reply_to_address, email.return_path,
                  *email.to_addresses, *email.cc_addresses):
        if value and "@" in value:
            addresses.add(value.strip().lower())

    # -- addresses appearing in the body ------------------------------------
    for found in EMAIL_RE.findall(email.body_text or ""):
        addresses.add(found.lower())

    for address in addresses:
        domain = address.rsplit("@", 1)[-1]
        if domain:
            domains.add(normalise_domain(domain))

    # -- URLs and their hosts -----------------------------------------------
    for url in email.urls:
        urls.add(normalise_url(url.raw))
        if url.host:
            if url.is_ip_literal:
                if _is_routable(url.host):
                    ips.add(url.host)
            else:
                domains.add(normalise_domain(url.host))

    # -- IPs from the delivery chain ----------------------------------------
    for hop in email.received_chain:
        for found in IPV4_RE.findall(hop):
            if _is_routable(found):
                ips.add(found)

    # -- attachment hashes ---------------------------------------------------
    for item in email.attachments:
        if item.sha256:
            hashes.add(item.sha256.lower())

    return {
        "email_addresses": sorted(addresses),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "ipv4": sorted(ips),
        "attachment_sha256": sorted(hashes),
    }


def flatten(iocs: dict[str, list[str]]) -> list[tuple[str, str]]:
    """Flatten to (kind, value) pairs for correlation storage."""
    return [(kind, value) for kind, values in iocs.items() for value in values]
