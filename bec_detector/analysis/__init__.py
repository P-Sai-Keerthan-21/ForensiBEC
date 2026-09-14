"""Stage 2 - Analysis.

Feature extraction across the three evidence families the brief calls for:

    sender.py    identity and header-authentication features
    behavior.py  sending-pattern features, baselined across the corpus
    text.py      linguistic features (urgency, authority, payment intent)

Every extractor returns `Indicator` objects carrying their own evidence string.
"""

from .sender import analyse_sender
from .behavior import BehaviorBaseline, analyse_behavior
from .text import analyse_text, get_nlp_status

__all__ = [
    "analyse_sender",
    "BehaviorBaseline",
    "analyse_behavior",
    "analyse_text",
    "get_nlp_status",
]
