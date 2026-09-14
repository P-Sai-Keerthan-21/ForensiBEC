"""Static URL analysis.

STATIC ONLY. This module never resolves, requests, follows or otherwise
contacts any URL found in evidence. Every judgement below is made from the
URL string itself. Contacting attacker infrastructure from an investigator's
machine would leak the fact of the investigation and could alter the evidence.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..config import FREEMAIL_DOMAINS, TRUSTED_DOMAINS, WEIGHTS
from ..models import Category, Confidence, EmailArtifact, Indicator, Severity, UrlArtifact

URL_PATTERN = re.compile(r"""https?://[^\s<>"'\)\]]+""", re.I)

# An anchor whose visible text is itself a URL, e.g.
#   <a href="http://evil.test">http://bank.example</a>
HTML_ANCHOR = re.compile(
    r"""<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
    re.I | re.S,
)

IPV4_LITERAL = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Paths that commonly front credential-harvesting pages.
SUSPICIOUS_PATH_TERMS = (
    "login", "signin", "verify", "verification", "account", "secure",
    "update", "confirm", "password", "webmail", "owa", "auth", "invoice",
    "payment", "wire",
)

# URL shorteners hide the true destination from the recipient.
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

# Characters that do not belong in a legitimate hostname.
ODD_HOST_CHARS = re.compile(r"[^a-z0-9.\-]", re.I)


def _strip_trailing_punctuation(url: str) -> str:
    """Remove sentence punctuation that regex capture drags in."""
    return url.rstrip(".,;:!?)>\"'")


def extract_urls(body: str, is_html: bool = False) -> list[UrlArtifact]:
    """Parse every URL in the body into a statically-described artifact."""
    if not body:
        return []

    artifacts: list[UrlArtifact] = []
    seen: set[str] = set()

    # Anchor text/href disagreement is only meaningful in HTML bodies.
    mismatches: dict[str, str] = {}
    if is_html or "<a " in body.lower():
        for href, text in HTML_ANCHOR.findall(body):
            visible = re.sub(r"<[^>]+>", "", text).strip()
            if not visible.lower().startswith(("http://", "https://")):
                continue
            href_host = urlparse(href).netloc.lower()
            text_host = urlparse(visible).netloc.lower()
            if href_host and text_host and href_host != text_host:
                mismatches[href] = visible

    for match in URL_PATTERN.findall(body):
        raw = _strip_trailing_punctuation(match)
        if raw in seen:
            continue
        seen.add(raw)

        try:
            parsed = urlparse(raw)
        except Exception:
            continue

        host = (parsed.hostname or "").lower()
        artifacts.append(UrlArtifact(
            raw=raw,
            scheme=(parsed.scheme or "").lower(),
            host=host,
            path=parsed.path or "",
            is_ip_literal=bool(IPV4_LITERAL.match(host)),
            is_punycode=host.startswith("xn--") or ".xn--" in host,
            uses_https=(parsed.scheme or "").lower() == "https",
            length=len(raw),
            display_mismatch=mismatches.get(raw, ""),
        ))

    return artifacts


def _indicator(code: str, title: str, severity: Severity, evidence: str,
               explanation: str, recommendation: str, confidence: float = 1.0,
               basis: Confidence = Confidence.OBSERVED,
               mitre: list[str] | None = None) -> Indicator:
    return Indicator(
        code=code, title=title, category=Category.URL, severity=severity,
        weight=WEIGHTS.get(code, 5.0), confidence=confidence,
        evidence=evidence, explanation=explanation,
        basis=basis, recommendation=recommendation, mitre=mitre or [],
    )


def analyse_urls(email: EmailArtifact) -> list[Indicator]:
    """Raise indicators for statically suspicious URLs in the body."""
    indicators: list[Indicator] = []
    urls = email.urls
    if not urls:
        return indicators

    for url in urls:
        # -- Anchor text disagrees with destination ------------------------
        if url.display_mismatch:
            indicators.append(_indicator(
                "URL_DISPLAY_MISMATCH", "Link text does not match its destination",
                Severity.CRITICAL,
                evidence=f"displayed {url.display_mismatch!r} -> actually links to {url.raw!r}",
                explanation=(
                    "The visible link text names a different host than the link "
                    "actually points to. The recipient cannot see the real "
                    "destination without inspecting the HTML."
                ),
                recommendation=(
                    "Treat the destination host as hostile. Do not open it; "
                    "record it as an IOC and block it at the mail gateway."
                ),
                mitre=["T1566.002"],
            ))

        # -- Raw IP address instead of a hostname ---------------------------
        if url.is_ip_literal:
            indicators.append(_indicator(
                "URL_IP_LITERAL", "Link points at a bare IP address",
                Severity.HIGH,
                evidence=f"{url.raw} (host {url.host})",
                explanation=(
                    "Legitimate business services are reached by hostname. A raw "
                    "IP avoids domain registration and reputation entirely."
                ),
                recommendation="Record the IP as an IOC and check egress logs for connections to it.",
                mitre=["T1566.002"],
            ))

        # -- Punycode / IDN ------------------------------------------------
        if url.is_punycode:
            decoded = url.host
            try:
                decoded = url.host.encode("ascii").decode("idna")
            except Exception:
                pass
            indicators.append(_indicator(
                "URL_PUNYCODE", "Link uses a punycode (internationalised) host",
                Severity.HIGH,
                evidence=f"{url.host} decodes to {decoded!r}",
                explanation=(
                    "Punycode hosts can render as characters visually identical "
                    "to a familiar brand while being an entirely different domain."
                ),
                recommendation="Compare the decoded form against your known-good domains before trusting it.",
                mitre=["T1566.002"],
            ))

        # -- URL shortener --------------------------------------------------
        if url.host in SHORTENER_HOSTS:
            indicators.append(_indicator(
                "URL_SHORTENER", "Link uses a URL shortening service",
                Severity.MEDIUM,
                evidence=url.raw,
                explanation=(
                    "A shortener conceals the true destination from both the "
                    "recipient and mail-gateway URL inspection."
                ),
                recommendation=(
                    "Expand the link in an isolated analysis environment only. "
                    "This tool does not resolve it automatically."
                ),
                confidence=0.8,
            ))

        # -- Credential-harvest style path ----------------------------------
        lowered = url.path.lower()
        hits = [t for t in SUSPICIOUS_PATH_TERMS if t in lowered]
        if hits and url.host not in TRUSTED_DOMAINS:
            indicators.append(_indicator(
                "URL_SUSPICIOUS_PATH", "Link path suggests a credential or payment page",
                Severity.MEDIUM,
                evidence=f"{url.raw} (path terms: {', '.join(hits[:4])})",
                explanation=(
                    "The path resembles a sign-in or payment endpoint while the "
                    "host is not a known-good domain."
                ),
                recommendation="Do not open. Verify any account action through the provider's official site.",
                basis=Confidence.INFERRED,
                confidence=0.7,
                mitre=["T1566.002"],
            ))

        # -- Plain HTTP for an action link -----------------------------------
        if not url.uses_https and hits:
            indicators.append(_indicator(
                "URL_NO_TLS", "Action link served over plain HTTP",
                Severity.LOW,
                evidence=url.raw,
                explanation=(
                    "A sign-in or payment style link without TLS would expose "
                    "submitted data in transit, and is inconsistent with a "
                    "legitimate corporate service."
                ),
                recommendation="Treat any credentials that may have been submitted here as compromised.",
                confidence=0.6,
            ))

        # -- Odd characters in the hostname ----------------------------------
        if ODD_HOST_CHARS.search(url.host):
            indicators.append(_indicator(
                "URL_ODD_HOST", "Hostname contains unusual characters",
                Severity.MEDIUM,
                evidence=f"host {url.host!r}",
                explanation="The hostname contains characters outside the normal "
                            "letter/digit/hyphen set, a common obfuscation.",
                recommendation="Record as an IOC and inspect in an isolated environment.",
                confidence=0.7,
            ))

        # -- Lookalike of a trusted domain -----------------------------------
        for trusted in TRUSTED_DOMAINS:
            if url.host and url.host != trusted and trusted.split(".")[0] in url.host:
                if not url.host.endswith(trusted):
                    indicators.append(_indicator(
                        "URL_LOOKALIKE_HOST", "Link host imitates a trusted domain",
                        Severity.HIGH,
                        evidence=f"link host {url.host!r} vs trusted {trusted!r}",
                        explanation=(
                            "The link host embeds the trusted brand name without "
                            "actually being that domain."
                        ),
                        recommendation="Block the host at the gateway and record it as an IOC.",
                        mitre=["T1566.002"],
                    ))
                break

    # -- Overall volume ------------------------------------------------------
    if len(urls) > 12:
        indicators.append(_indicator(
            "URL_HIGH_VOLUME", "Unusually high number of links",
            Severity.LOW,
            evidence=f"{len(urls)} URLs in the message body",
            explanation="High link counts are more typical of bulk mail than of a "
                        "direct business instruction.",
            recommendation="Consider whether the message is bulk marketing rather than targeted.",
            basis=Confidence.INFERRED,
            confidence=0.5,
        ))

    return indicators
