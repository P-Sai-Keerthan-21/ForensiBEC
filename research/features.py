"""Feature extraction for the ML research layer.

This module does NOT reimplement detection. It runs the existing forensic
analysers and records what they observed, so that an ablation over feature
groups is an ablation over *real evidence families* rather than over proxies
invented for the experiment.

Feature groups
--------------
Each group corresponds to one evidence family in the forensic engine. The
ablation study (research/ablation.py) enables them cumulatively to answer:
"which evidence sources contribute to BEC detection?"

    text        raw subject+body, vectorised as TF-IDF (word and char n-grams)
    header      envelope/header facts: auth results, Reply-To, Return-Path
    identity    display-name spoofing, lookalike domains, freemail exec claims
    behaviour   corpus-baselined sending-pattern deviation
    nlp         urgency, secrecy, authority - social-engineering pressure
    financial   payment, banking change, gift card, money entities
    thread      conversation reconstruction findings
    stylometry  per-sender writing-style deviation
    artifact    static URL and attachment findings

Label leakage
-------------
No feature is derived from the ground-truth label. Indicator codes are engine
*outputs* computed from the message alone; using them is the whole point of
the experiment, which compares text-only classification against evidence
fusion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from bec_detector.acquisition import load_path
from bec_detector.analysis import (
    BehaviorBaseline,
    StyleBaseline,
    ThreadIndex,
    analyse_attachments,
    analyse_sender,
    analyse_text,
    analyse_urls,
)
from bec_detector.config import FREEMAIL_DOMAINS, TRUSTED_DOMAINS
from bec_detector.models import Category, EmailArtifact, Indicator

# Ordered so that a feature vector is stable across runs.
FEATURE_GROUPS: tuple[str, ...] = (
    "text", "header", "identity", "behaviour", "nlp",
    "financial", "thread", "stylometry", "artifact",
)

# Indicator codes assigned to each group. A code appearing in no group is
# ignored rather than silently defaulting, so the mapping stays auditable.
GROUP_CODES: dict[str, tuple[str, ...]] = {
    "header": (
        "SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL", "NO_AUTH_RESULTS",
        "SUSPICIOUS_HOP_COUNT", "REPLY_TO_MISMATCH", "REPLY_TO_FREEMAIL",
        "RETURN_PATH_MISMATCH",
    ),
    "identity": (
        "DISPLAY_NAME_IMPERSONATION", "DISPLAY_NAME_EMBEDS_OTHER_ADDRESS",
        "DISPLAY_NAME_IS_EMAIL", "LOOKALIKE_DOMAIN", "FREEMAIL_EXEC_CLAIM",
    ),
    "behaviour": (
        "FIRST_TIME_SENDER", "DISPLAY_NAME_CHANGED", "OFF_HOURS_SEND",
        "UNUSUAL_RECIPIENT_SET", "NEW_DOMAIN_FOR_KNOWN_NAME",
    ),
    "nlp": (
        "URGENCY_LANGUAGE", "SECRECY_REQUEST", "AUTHORITY_PRESSURE",
        "CREDENTIAL_SOLICITATION", "THREAD_HIJACK_MARKERS",
    ),
    "financial": (
        "PAYMENT_REQUEST", "BANKING_CHANGE_REQUEST", "GIFT_CARD_REQUEST",
        "MONEY_ENTITY_PRESENT",
    ),
    "thread": (
        "THREAD_FABRICATED_REPLY", "THREAD_UNKNOWN_PARENT",
        "THREAD_NEW_PARTICIPANT", "THREAD_REPLYTO_INTRODUCED",
        "THREAD_SENDER_DIVERGENCE", "THREAD_PAYMENT_PIVOT",
    ),
    "stylometry": (
        "STYLE_DEVIATION", "STYLE_GREETING_CHANGE", "STYLE_SIGNATURE_CHANGE",
    ),
    "artifact": (
        "URL_DISPLAY_MISMATCH", "URL_IP_LITERAL", "URL_PUNYCODE",
        "URL_SHORTENER", "URL_SUSPICIOUS_PATH", "URL_NO_TLS", "URL_ODD_HOST",
        "URL_LOOKALIKE_HOST", "URL_HIGH_VOLUME",
        "ATTACHMENT_TYPE_MISMATCH", "ATTACHMENT_EXECUTABLE",
        "ATTACHMENT_MACRO_CAPABLE", "ATTACHMENT_ARCHIVE",
        "ATTACHMENT_DOUBLE_EXTENSION", "ATTACHMENT_EMPTY",
    ),
}

# Continuous features per group, computed directly from the artifact.
NUMERIC_FEATURES: dict[str, tuple[str, ...]] = {
    "header": ("n_received_hops", "has_reply_to", "reply_to_is_freemail",
               "has_return_path", "auth_pass_count", "auth_fail_count"),
    "identity": ("sender_is_internal", "sender_is_freemail", "display_has_title",
                 "display_name_length", "domain_part_count", "domain_length"),
    "behaviour": ("send_hour", "is_off_hours", "n_recipients", "n_cc"),
    "nlp": ("n_exclamations", "n_uppercase_words", "subject_length"),
    "financial": ("has_iban_pattern", "has_currency_pattern"),
    "thread": ("has_in_reply_to", "n_references", "subject_is_reply"),
    "stylometry": ("body_length", "word_count", "mean_word_length",
                   "type_token_ratio"),
    "artifact": ("n_urls", "n_attachments", "max_url_length"),
}

EXEC_TITLES = ("ceo", "cfo", "coo", "cto", "director", "president",
               "chairman", "vp", "controller", "treasurer")


@dataclass
class ExtractedSample:
    """One message reduced to text plus grouped structured features."""

    name: str
    label: int                       # 1 = MALICIOUS, 0 = BENIGN
    label_name: str
    family: str
    text: str
    groups: dict[str, dict[str, float]] = field(default_factory=dict)

    def vector_for(self, groups: list[str]) -> dict[str, float]:
        """Flatten the named groups into one namespaced feature mapping."""
        out: dict[str, float] = {}
        for group in groups:
            for key, value in self.groups.get(group, {}).items():
                out[f"{group}::{key}"] = value
        return out


def _numeric(email: EmailArtifact) -> dict[str, dict[str, float]]:
    """Continuous features, grouped. Computed from the artifact only."""
    import re

    body = email.body_text or ""
    words = re.findall(r"[A-Za-z']+", body)
    word_count = len(words) or 1
    auth = (email.auth_results or "").lower()
    domain = email.from_domain

    display_lower = (email.from_display or "").lower()

    return {
        "header": {
            "n_received_hops": float(len(email.received_chain)),
            "has_reply_to": float(bool(email.reply_to_address)),
            "reply_to_is_freemail": float(email.reply_to_domain in FREEMAIL_DOMAINS),
            "has_return_path": float(bool(email.return_path)),
            "auth_pass_count": float(auth.count("=pass")),
            "auth_fail_count": float(auth.count("=fail") + auth.count("=softfail")),
        },
        "identity": {
            "sender_is_internal": float(domain in TRUSTED_DOMAINS),
            "sender_is_freemail": float(domain in FREEMAIL_DOMAINS),
            "display_has_title": float(any(t in display_lower for t in EXEC_TITLES)),
            "display_name_length": float(len(email.from_display or "")),
            "domain_part_count": float(domain.count(".") + 1 if domain else 0),
            "domain_length": float(len(domain)),
        },
        "behaviour": {
            "send_hour": float(email.date_utc.hour) if email.date_utc else -1.0,
            "is_off_hours": float(
                email.date_utc is not None and not (7 <= email.date_utc.hour < 20)
            ),
            "n_recipients": float(len(email.to_addresses)),
            "n_cc": float(len(email.cc_addresses)),
        },
        "nlp": {
            "n_exclamations": float(body.count("!")),
            "n_uppercase_words": float(sum(1 for w in words if len(w) > 3 and w.isupper())),
            "subject_length": float(len(email.subject or "")),
        },
        "financial": {
            "has_iban_pattern": float(bool(re.search(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,}", body))),
            "has_currency_pattern": float(
                bool(re.search(r"[$€£]\s?\d|(?:usd|eur|gbp)\s?\d", body, re.I))
            ),
        },
        "thread": {
            "has_in_reply_to": float(bool(email.in_reply_to)),
            "n_references": float(len(email.references)),
            "subject_is_reply": float(
                (email.subject or "").lower().startswith(("re:", "fw:", "fwd:"))
            ),
        },
        "stylometry": {
            "body_length": float(len(body)),
            "word_count": float(len(words)),
            "mean_word_length": float(np.mean([len(w) for w in words])) if words else 0.0,
            "type_token_ratio": len({w.lower() for w in words}) / word_count,
        },
        "artifact": {
            "n_urls": float(len(email.urls)),
            "n_attachments": float(len(email.attachments)),
            "max_url_length": float(max((u.length for u in email.urls), default=0)),
        },
    }


def _indicator_features(indicators: list[Indicator]) -> dict[str, dict[str, float]]:
    """One binary feature per indicator code, bucketed into its group."""
    fired = {i.code for i in indicators}
    out: dict[str, dict[str, float]] = {g: {} for g in FEATURE_GROUPS}
    for group, codes in GROUP_CODES.items():
        for code in codes:
            out[group][f"ind_{code}"] = float(code in fired)
    return out


class FeatureExtractor:
    """Runs the forensic analysers over a corpus and emits ML samples.

    The corpus is observed in full before any message is featurised, mirroring
    the engine's own two-pass design: behavioural, thread and stylometric
    features describe deviation, which is undefined without a baseline.
    """

    def __init__(self) -> None:
        self.behaviour = BehaviorBaseline()
        self.threads = ThreadIndex()
        self.style = StyleBaseline()
        self._fitted = False

    def fit(self, emails: list[EmailArtifact]) -> None:
        self.behaviour.observe_all(emails)
        self.threads.observe_all(emails)
        self.style.observe_all(emails)
        self._fitted = True

    def extract(self, email: EmailArtifact, name: str,
                label_name: str, family: str) -> ExtractedSample:
        if not self._fitted:
            raise RuntimeError("FeatureExtractor.fit() must be called before extract()")

        indicators: list[Indicator] = []
        indicators.extend(analyse_sender(email))
        indicators.extend(analyse_text(email))
        indicators.extend(self.behaviour.analyse(email))
        indicators.extend(self.threads.analyse(email))
        indicators.extend(analyse_urls(email))
        indicators.extend(analyse_attachments(email))
        style_indicators, _ = self.style.analyse(email)
        indicators.extend(style_indicators)

        groups = _indicator_features(indicators)
        for group, values in _numeric(email).items():
            groups.setdefault(group, {}).update(values)

        groups["text"] = {}  # text is vectorised separately, not as scalars

        return ExtractedSample(
            name=name,
            label=1 if label_name == "MALICIOUS" else 0,
            label_name=label_name,
            family=family,
            text=f"{email.subject or ''}\n{email.body_text or ''}",
            groups=groups,
        )


def load_split(path: str | Path) -> list[ExtractedSample]:
    """Load one corpus split and featurise every message in it."""
    import json

    path = Path(path)
    labels_file = path / "labels.json"
    if not labels_file.exists():
        raise FileNotFoundError(
            f"{labels_file} not found - run: python data/build_research_corpus.py"
        )

    labels = json.loads(labels_file.read_text(encoding="utf-8"))
    emails = load_path(path, examiner="research-pipeline")

    extractor = FeatureExtractor()
    extractor.fit(emails)

    samples: list[ExtractedSample] = []
    for email in emails:
        filename = Path(email.custody.source_path).name
        meta = labels.get(filename)
        if not meta:
            continue
        samples.append(extractor.extract(
            email, filename, meta["label"], meta["family"]
        ))
    return samples


def feature_schema(samples: list[ExtractedSample]) -> dict[str, Any]:
    """Describe the feature space, for the reproducibility record."""
    schema: dict[str, Any] = {"groups": {}, "total_structured_features": 0}
    if not samples:
        return schema

    for group in FEATURE_GROUPS:
        keys = sorted(samples[0].groups.get(group, {}))
        schema["groups"][group] = {"count": len(keys), "features": keys}
        schema["total_structured_features"] += len(keys)

    schema["text_representation"] = (
        "TF-IDF, word 1-2 grams (max 5000) + char_wb 3-5 grams (max 5000)"
    )
    return schema
