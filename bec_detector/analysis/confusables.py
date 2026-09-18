"""Unicode confusable / homoglyph analysis for domain names.

What this replaces
------------------
The original comparer lower-cased a domain and then *deleted* every character
outside a-z. A single Cyrillic 'о' in "nоrthwind" was therefore caught only by
accident - deleting it left a string one edit away from the real name. Three
homoglyphs would exceed the edit-distance threshold, punycode (xn--) labels
normalised to meaningless strings, and the evidence never said WHICH characters
were deceptive.

Method
------
1. IDNA decode. Each ``xn--`` label is decoded to its Unicode form, so a
   punycode domain is compared on what a recipient actually sees rendered.
   Malformed labels are recorded as an error and left as-is - never raised.
2. NFKC normalisation. Folds compatibility forms (fullwidth letters, ligatures)
   to their canonical characters.
3. Confusable skeleton. Characters from Cyrillic, Greek and other scripts that
   render like Latin letters are mapped to the Latin letter they imitate, using
   a curated subset of the Unicode TR39 confusables data covering the
   characters actually used in domain spoofing. Latin letters with diacritics
   are reduced to their base letter. Digit substitutions (0->o, 1->l) are
   handled as before.
4. Script analysis. Each label is checked for mixing Latin with Cyrillic or
   Greek letters - a combination with essentially no legitimate use inside a
   single label, and the signature of a homograph attack.

False-positive discipline
-------------------------
A legitimate internationalised domain (münchen.de, пример.рф, παράδειγμα.gr)
is written in ONE script. It is never flagged merely for containing non-ASCII
characters. It is flagged only if its skeleton imitates a trusted domain, or if
it mixes Latin with Cyrillic/Greek inside one label.

Limitations
-----------
The confusable table is a curated subset, not the full TR39 dataset (~6,000
entries). Scripts beyond Latin/Cyrillic/Greek/fullwidth - Armenian, Cherokee,
mathematical alphanumerics - are only partially covered. See docs/limitations.md.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Confusable table - character -> the Latin letter(s) it imitates.
# Source: curated from Unicode TR39 confusables.txt, restricted to characters
# that render as a single Latin letter in common UI fonts.
# ---------------------------------------------------------------------------

CONFUSABLES: dict[str, str] = {
    # Cyrillic lower case
    "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i",
    "ј": "j", "к": "k", "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "ѕ": "s", "т": "t", "у": "y", "х": "x", "ү": "y", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "ɡ": "g", "ы": "bl", "ь": "b", "п": "n", "г": "r",
    # Cyrillic upper case
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o",
    "Р": "p", "С": "c", "Т": "t", "Х": "x", "У": "y", "І": "i", "Ј": "j",
    "Ѕ": "s", "Ԁ": "d", "Ԛ": "q", "Ԝ": "w",
    # Greek lower case
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w",
    # Greek upper case
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k",
    "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    # Latin look-alikes outside basic a-z
    "ı": "i", "ȷ": "j", "ł": "l", "ɑ": "a", "ƅ": "b", "ɩ": "i", "ʟ": "l",
    "ɴ": "n", "ʀ": "r", "ꜱ": "s", "ᴠ": "v", "ᴡ": "w", "ᴢ": "z",
    # Armenian
    "օ": "o", "ս": "u", "զ": "q", "ց": "g", "հ": "h",
}

# ASCII substitutions carried over unchanged from the original comparer, so the
# behaviour on pure-ASCII domains is byte-identical.
DIGIT_MAP: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "|": "l",
}

TRACKED_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN")


@dataclass
class ConfusableChar:
    char: str
    codepoint: str
    name: str
    script: str
    imitates: str
    position: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DomainAnalysis:
    """Everything the investigator needs to judge a domain's appearance."""

    original: str
    unicode_form: str
    ascii_form: str
    skeleton: str
    is_idn: bool
    scripts: list[str] = field(default_factory=list)
    mixed_script_labels: list[str] = field(default_factory=list)
    confusable_chars: list[ConfusableChar] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    best_match: str = ""
    similarity: float = 0.0
    edit_distance: int | None = None
    # True only when the skeleton is within the look-alike threshold of a
    # trusted domain. A distant 'closest match' is not evidence of anything.
    resembles_trusted: bool = False

    @property
    def is_mixed_script(self) -> bool:
        return bool(self.mixed_script_labels)

    @property
    def has_confusables(self) -> bool:
        return bool(self.confusable_chars)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["is_mixed_script"] = self.is_mixed_script
        data["has_confusables"] = self.has_confusables
        return data


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def script_of(char: str) -> str:
    """The Unicode script of a letter, from its character name.

    Only the scripts relevant to domain spoofing are distinguished; anything
    else is COMMON (digits, hyphen) or OTHER.
    """
    if not char.isalpha():
        return "COMMON"
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "OTHER"
    for script in TRACKED_SCRIPTS:
        if name.startswith(script):
            return script
    if name.startswith("FULLWIDTH LATIN"):
        return "LATIN"
    return "OTHER"


def decode_idna(domain: str) -> tuple[str, list[str]]:
    """Decode every xn-- label to Unicode. Never raises.

    Labels are decoded individually so that one malformed label does not
    prevent the rest of the domain from being analysed.
    """
    errors: list[str] = []
    labels = []
    for label in domain.split("."):
        if label.lower().startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, ValueError) as exc:
                errors.append(f"malformed punycode label {label!r}: {type(exc).__name__}")
                labels.append(label)
        else:
            labels.append(label)
    return ".".join(labels), errors


def encode_idna(domain: str) -> tuple[str, list[str]]:
    """ASCII (punycode) form of a Unicode domain. Never raises."""
    errors: list[str] = []
    labels = []
    for label in domain.split("."):
        if not label or label.isascii():
            labels.append(label)
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except (UnicodeError, ValueError) as exc:
            errors.append(f"label {label!r} cannot be IDNA-encoded: {type(exc).__name__}")
            labels.append(label)
    return ".".join(labels), errors


def _strip_marks(text: str) -> str:
    """Remove combining diacritics: 'ü' -> 'u'."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def skeleton(label: str) -> str:
    """Reduce a label to the Latin letters it visually presents.

    For a pure-ASCII label this is exactly the original comparer's output:
    lower-case, digit substitution, then non-letters removed.
    """
    text = unicodedata.normalize("NFKC", label)
    out: list[str] = []
    for ch in text:
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
            continue
        lowered = ch.lower()
        if lowered in CONFUSABLES:
            out.append(CONFUSABLES[lowered])
            continue
        if not lowered.isascii():
            lowered = _strip_marks(lowered)
        out.append(lowered)
    reduced = "".join(out).translate(str.maketrans(DIGIT_MAP))
    return re.sub(r"[^a-z]", "", reduced)


def core_label(domain: str) -> str:
    """The label that carries the brand: the leftmost one, as before."""
    return domain.split(".")[0] if domain else ""


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse_domain(domain: str, trusted: set[str] | frozenset[str] = frozenset()) -> DomainAnalysis:
    """Full confusable analysis of one domain. Never raises on bad input."""
    raw = (domain or "").strip().strip(".")
    errors: list[str] = []

    if not raw:
        return DomainAnalysis(original=domain or "", unicode_form="", ascii_form="",
                              skeleton="", is_idn=False, errors=["empty domain"])

    if len(raw) > 253:
        errors.append("domain exceeds 253 characters")
        raw = raw[:253]

    unicode_form, decode_errors = decode_idna(raw)
    errors.extend(decode_errors)
    unicode_form = unicodedata.normalize("NFKC", unicode_form).lower()
    ascii_form, encode_errors = encode_idna(unicode_form)
    errors.extend(encode_errors)

    confusables: list[ConfusableChar] = []
    scripts: set[str] = set()
    mixed: list[str] = []

    position = 0
    for label in unicode_form.split("."):
        label_scripts = set()
        for ch in label:
            script = script_of(ch)
            if script not in ("COMMON",):
                label_scripts.add(script)
            if not ch.isascii():
                imitates = CONFUSABLES.get(ch) or CONFUSABLES.get(ch.lower())
                if imitates:
                    try:
                        name = unicodedata.name(ch)
                    except ValueError:
                        name = "UNKNOWN"
                    confusables.append(ConfusableChar(
                        char=ch, codepoint=f"U+{ord(ch):04X}", name=name,
                        script=script, imitates=imitates, position=position,
                    ))
            position += 1
        position += 1  # the dot
        scripts |= label_scripts
        if "LATIN" in label_scripts and label_scripts & {"CYRILLIC", "GREEK", "ARMENIAN"}:
            mixed.append(label)

    result = DomainAnalysis(
        original=domain,
        unicode_form=unicode_form,
        ascii_form=ascii_form,
        skeleton=skeleton(core_label(unicode_form)),
        is_idn=unicode_form != ascii_form or ascii_form.startswith("xn--") or ".xn--" in ascii_form,
        scripts=sorted(scripts),
        mixed_script_labels=mixed,
        confusable_chars=confusables,
        errors=errors,
    )

    best, best_distance = "", None
    # Rank by skeleton distance, then by distance between the full rendered
    # domains, so that northwind-l0gistics.com is matched to the .com it
    # imitates rather than to a .co.uk sibling that merely sorts first.
    ranked = sorted(
        trusted,
        key=lambda t: (levenshtein(result.skeleton, skeleton(core_label(t))),
                       levenshtein(unicode_form, t), t),
    )
    if ranked:
        best = ranked[0]
        best_distance = levenshtein(result.skeleton, skeleton(core_label(best)))
    if best:
        target = skeleton(core_label(best))
        longest = max(len(result.skeleton), len(target)) or 1
        result.best_match = best
        result.edit_distance = best_distance
        result.similarity = round(1 - (best_distance or 0) / longest, 3)
        result.resembles_trusted = (best_distance or 0) <= 2 and unicode_form not in trusted

    return result


def describe(analysis: DomainAnalysis) -> str:
    """One-line evidence string listing exactly which characters deceive."""
    parts = [f"original {analysis.original!r}"]
    if analysis.unicode_form != analysis.original.lower():
        parts.append(f"renders as {analysis.unicode_form!r}")
    if analysis.ascii_form != analysis.unicode_form:
        parts.append(f"punycode {analysis.ascii_form!r}")
    parts.append(f"normalised skeleton {analysis.skeleton!r}")
    if analysis.confusable_chars:
        chars = ", ".join(
            f"{c.char!r} {c.codepoint} {c.script} imitating {c.imitates!r}"
            for c in analysis.confusable_chars[:6]
        )
        parts.append(f"confusable characters: {chars}")
    if analysis.best_match and analysis.resembles_trusted:
        parts.append(
            f"closest trusted domain {analysis.best_match!r} "
            f"(similarity {analysis.similarity:.2f}, edit distance {analysis.edit_distance})"
        )
    return " | ".join(parts)
