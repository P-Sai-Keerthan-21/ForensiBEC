"""Stage 2 - Analysis.

Feature extraction across the evidence families the brief calls for:

    sender.py       identity and header-authentication features
    behavior.py     sending-pattern features, baselined across the corpus
    text.py         linguistic features (urgency, authority, payment intent)
    thread.py       conversation reconstruction and hijack indicators
    stylometry.py   per-sender writing-style comparison
    urls.py         static URL analysis (never contacts a URL)
    attachments.py  static attachment analysis (never executes a file)

Every extractor returns `Indicator` objects carrying their own evidence string.
"""

from .attachments import analyse_attachments, describe_attachment, sniff_type
from .behavior import BehaviorBaseline, analyse_behavior
from .sender import analyse_sender
from .stylometry import StyleBaseline, style_features
from .text import analyse_text, get_nlp_status
from .thread import ThreadIndex, analyse_thread, normalise_subject
from .urls import analyse_urls, extract_urls

__all__ = [
    "analyse_sender",
    "BehaviorBaseline", "analyse_behavior",
    "analyse_text", "get_nlp_status",
    "ThreadIndex", "analyse_thread", "normalise_subject",
    "StyleBaseline", "style_features",
    "analyse_urls", "extract_urls",
    "analyse_attachments", "describe_attachment", "sniff_type",
]
