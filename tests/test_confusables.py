"""Unicode confusable / homoglyph regression tests.

The original comparer deleted non-ASCII characters, so single homoglyphs were
caught only by accident and punycode was missed outright. These tests pin the
genuine behaviour: decode, normalise, map confusables, detect mixed scripts,
explain which characters deceive - and do NOT flag legitimate single-script
internationalised domains.
"""

from __future__ import annotations

import re
from email.message import EmailMessage

import pytest

from bec_detector.acquisition import load_bytes
from bec_detector.analysis.confusables import (
    analyse_domain,
    decode_idna,
    describe,
    encode_idna,
    script_of,
    skeleton,
)
from bec_detector.analysis.sender import _normalise_domain, analyse_sender
from bec_detector.analysis.urls import analyse_urls

TRUSTED = frozenset({"northwind-logistics.com"})
LEGIT = "northwind-logistics.com"

CYR_O = "о"   # Cyrillic small o
CYR_A = "а"   # Cyrillic small a
CYR_I = "і"   # Cyrillic small byelorussian-ukrainian i
GRK_O = "ο"   # Greek small omicron


def _msg(from_header: str, body: str = "Hello") -> bytes:
    m = EmailMessage()
    m["From"] = from_header
    m["To"] = "a@northwind-logistics.com"
    m["Subject"] = "test"
    m["Date"] = "Mon, 01 Sep 2026 09:00:00 +0000"
    m["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
    m.set_content(body)
    return m.as_bytes()


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def test_script_detection():
    assert script_of("a") == "LATIN"
    assert script_of(CYR_O) == "CYRILLIC"
    assert script_of(GRK_O) == "GREEK"
    assert script_of("-") == "COMMON"
    assert script_of("7") == "COMMON"


def test_punycode_decodes_to_unicode():
    puny = f"n{CYR_O}rthwind-logistics.com".encode("idna").decode()
    assert puny.startswith("xn--")
    decoded, errors = decode_idna(puny)
    assert decoded == f"n{CYR_O}rthwind-logistics.com"
    assert errors == []


def test_malformed_punycode_is_reported_not_raised():
    decoded, errors = decode_idna("xn--!!!invalid.com")
    assert errors, "a malformed label must be reported"
    assert decoded  # and analysis continues


def test_encode_roundtrip():
    unicode_domain = f"n{CYR_O}rthwind-logistics.com"
    ascii_form, errors = encode_idna(unicode_domain)
    assert ascii_form.startswith("xn--") and not errors
    assert decode_idna(ascii_form)[0] == unicode_domain


def test_skeleton_of_ascii_is_unchanged_behaviour():
    """ASCII behaviour must match the original comparer exactly."""
    assert skeleton("northwind-l0gistics") == "northwindlogistics"
    assert skeleton("NORTHWIND-LOGISTICS") == "northwindlogistics"
    assert skeleton("n0rthw1nd") == "northwlnd"


def test_fullwidth_is_folded_by_nfkc():
    assert skeleton("ｎorthwind-logistics") == "northwindlogistics"


def test_diacritics_are_reduced_to_base_letter():
    assert skeleton("münchen") == "munchen"


# ---------------------------------------------------------------------------
# Homoglyph detection - the cases the old comparer missed or caught by accident
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spoof,label", [
    (f"n{CYR_O}rthwind-logistics.com", "single cyrillic o"),
    (f"n{GRK_O}rthwind-logistics.com", "single greek omicron"),
    (f"northw{CYR_I}nd-logistics.com", "cyrillic i"),
    (f"n{CYR_O}rthwind-l{CYR_O}gistics.com", "two homoglyphs"),
    (f"n{CYR_O}rthw{CYR_I}nd-l{CYR_O}gistics.com", "three homoglyphs"),
])
def test_homoglyph_skeleton_matches_trusted_exactly(spoof, label):
    """Every homoglyph variant must collapse to the SAME skeleton - distance 0,
    not an accidental edit distance of 1 or 2."""
    assert _normalise_domain(spoof) == _normalise_domain(LEGIT), label
    result = analyse_domain(spoof, TRUSTED)
    assert result.edit_distance == 0
    assert result.similarity == 1.0
    assert result.best_match == LEGIT


def test_three_homoglyphs_now_detected():
    """Regression: 3 deletions exceeded the old distance-2 threshold."""
    spoof = f"n{CYR_O}rthw{CYR_I}nd-l{CYR_O}gistics.com"
    indicators = analyse_sender(load_bytes(_msg(f"Ravi <ravi@{spoof}>"), "t.eml"))
    assert "LOOKALIKE_DOMAIN" in {i.code for i in indicators}


def test_punycode_sender_detected():
    """Regression: xn-- domains previously normalised to garbage."""
    puny = f"n{CYR_O}rthwind-logistics.com".encode("idna").decode()
    indicators = analyse_sender(load_bytes(_msg(f"Ravi <ravi@{puny}>"), "t.eml"))
    codes = {i.code for i in indicators}
    assert "LOOKALIKE_DOMAIN" in codes


def test_confusable_characters_are_named_in_evidence():
    spoof = f"n{CYR_O}rthwind-logistics.com"
    result = analyse_domain(spoof, TRUSTED)
    assert len(result.confusable_chars) == 1
    char = result.confusable_chars[0]
    assert char.codepoint == "U+043E"
    assert char.script == "CYRILLIC"
    assert char.imitates == "o"
    assert "CYRILLIC SMALL LETTER O" in char.name

    text = describe(result)
    assert "U+043E" in text and "imitating 'o'" in text
    assert "punycode" in text and "xn--" in text


def test_lookalike_indicator_explains_characters():
    spoof = f"n{CYR_O}rthwind-logistics.com"
    indicators = analyse_sender(load_bytes(_msg(f"Ravi <ravi@{spoof}>"), "t.eml"))
    lookalike = next(i for i in indicators if i.code == "LOOKALIKE_DOMAIN")
    assert "U+043E" in lookalike.evidence
    assert "non-Latin character" in lookalike.explanation


def test_mixed_script_is_flagged():
    spoof = f"n{CYR_O}rthwind-logistics.com"
    result = analyse_domain(spoof, TRUSTED)
    assert result.is_mixed_script
    assert "CYRILLIC" in result.scripts and "LATIN" in result.scripts

    indicators = analyse_sender(load_bytes(_msg(f"Ravi <ravi@{spoof}>"), "t.eml"))
    assert "MIXED_SCRIPT_DOMAIN" in {i.code for i in indicators}


# ---------------------------------------------------------------------------
# False-positive discipline - legitimate internationalised domains
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("domain", [
    "münchen.de",                       # Latin with diacritic
    "пример.рф",                        # all Cyrillic
    "παράδειγμα.gr",                    # all Greek
    "例え.jp",                           # Japanese
    "bücher-shop.example",
])
def test_legitimate_idn_is_not_mixed_script(domain):
    result = analyse_domain(domain, TRUSTED)
    assert not result.is_mixed_script, f"{domain} wrongly flagged as mixed-script"
    assert not result.errors


@pytest.mark.parametrize("domain", ["münchen.de", "пример.рф", "παράδειγμα.gr"])
def test_legitimate_idn_sender_raises_no_homograph_finding(domain):
    indicators = analyse_sender(load_bytes(_msg(f"Supplier <info@{domain}>"), "t.eml"))
    codes = {i.code for i in indicators}
    assert "LOOKALIKE_DOMAIN" not in codes
    assert "MIXED_SCRIPT_DOMAIN" not in codes


def test_trusted_domain_itself_is_not_flagged():
    indicators = analyse_sender(load_bytes(_msg(f"Priya <p@{LEGIT}>"), "t.eml"))
    codes = {i.code for i in indicators}
    assert "LOOKALIKE_DOMAIN" not in codes
    assert "MIXED_SCRIPT_DOMAIN" not in codes


def test_unrelated_ascii_domain_not_flagged():
    result = analyse_domain("bergindustrial.se", TRUSTED)
    assert result.edit_distance > 2
    assert not result.has_confusables and not result.is_mixed_script


# ---------------------------------------------------------------------------
# Malformed input safety
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "", ".", "..", "xn--", "xn--!!!.com", "a" * 400 + ".com",
    "‮evil.com", "exa\x00mple.com", "-.-", "..com",
])
def test_malformed_domains_never_raise(bad):
    result = analyse_domain(bad, TRUSTED)
    assert isinstance(result.skeleton, str)
    describe(result)  # must not raise either


def test_overlong_domain_is_truncated_and_reported():
    result = analyse_domain("a" * 400 + ".com", TRUSTED)
    assert any("253" in e for e in result.errors)


def test_normalise_domain_handles_empty():
    assert _normalise_domain("") == ""


# ---------------------------------------------------------------------------
# URL hosts
# ---------------------------------------------------------------------------

def test_homograph_url_host_detected():
    spoof = f"n{CYR_O}rthwind-logistics.com"
    email = load_bytes(_msg("IT <it@example.org>", f"Sign in at https://{spoof}/login now"),
                       "t.eml")
    indicators = analyse_urls(email)
    hits = [i for i in indicators if i.code == "URL_LOOKALIKE_HOST"]
    assert hits, "homograph link host was not detected"
    assert "U+043E" in hits[0].evidence


def test_legitimate_trusted_subdomain_link_not_flagged():
    email = load_bytes(
        _msg("IT <it@northwind-logistics.com>",
             "See https://intranet.northwind-logistics.com/handbook"),
        "t.eml",
    )
    assert "URL_LOOKALIKE_HOST" not in {i.code for i in analyse_urls(email)}


def test_research_corpus_domains_unaffected():
    """The ASCII path must stay byte-identical so research results cannot shift."""
    import glob
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    files = glob.glob(str(root / "data" / "samples" / "*.eml"))
    files += glob.glob(str(root / "data" / "research" / "*" / "*.eml"))

    def original(domain: str) -> str:
        table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                               "7": "t", "8": "b", "$": "s", "|": "l"})
        return re.sub(r"[^a-z]", "", domain.lower().split(".")[0].translate(table))

    domains: set[str] = set()
    for path in files:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        domains |= set(re.findall(r"@([\w.-]+)", text))

    ascii_domains = [d for d in domains if d.isascii()]
    assert ascii_domains
    assert all(original(d) == _normalise_domain(d) for d in ascii_domains)


# ---------------------------------------------------------------------------
# Regression: verdicts must not depend on the per-process hash seed
# ---------------------------------------------------------------------------

def test_url_lookalike_is_independent_of_hash_seed():
    """With two trusted domains, the original loop broke on whichever came
    first in set iteration order - which varies with PYTHONHASHSEED - and
    flagged a legitimate intranet link in roughly half of process runs."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    probe = (
        "from email.message import EmailMessage\n"
        "from bec_detector.acquisition import load_bytes\n"
        "from bec_detector.analysis.urls import analyse_urls\n"
        "m=EmailMessage(); m['From']='IT <it@northwind-logistics.com>'\n"
        "m['To']='a@northwind-logistics.com'; m['Subject']='x'\n"
        "m.set_content('See https://intranet.northwind-logistics.com/handbook')\n"
        "print(sorted(i.code for i in analyse_urls(load_bytes(m.as_bytes(),'t'))))\n"
    )
    root = Path(__file__).resolve().parent.parent
    outputs = set()
    for seed in ("0", "1", "2", "3", "4", "5"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        # Fixed interpreter and fixed code string - no user input reaches it.
        result = subprocess.run(
            [sys.executable, "-c", probe], cwd=root, env=env,
            capture_output=True, text=True, timeout=120, check=True,
        )
        outputs.add(result.stdout.strip())
    assert outputs == {"[]"}, f"verdict varies with hash seed: {outputs}"


def test_brand_suffix_host_is_flagged():
    """'evilnorthwind-logistics.com' ends with the brand text but is not ours."""
    email = load_bytes(
        _msg("IT <it@example.org>", "Go to https://evilnorthwind-logistics.com/login"),
        "t.eml",
    )
    assert "URL_LOOKALIKE_HOST" in {i.code for i in analyse_urls(email)}


def test_other_trusted_domain_is_own_estate():
    """A link to the .co.uk sibling is ours, not an imitation of .com."""
    email = load_bytes(
        _msg("IT <it@northwind-logistics.com>",
             "See https://portal.northwind-logistics.co.uk/login"),
        "t.eml",
    )
    assert "URL_LOOKALIKE_HOST" not in {i.code for i in analyse_urls(email)}


def test_own_estate_path_is_not_a_credential_page():
    """Regression: exact-match membership flagged our own portal subdomain."""
    email = load_bytes(
        _msg("AP <ap@northwind-logistics.com>",
             "Invoice here: https://portal.northwind-logistics.com/invoices/view"),
        "t.eml",
    )
    assert "URL_SUSPICIOUS_PATH" not in {i.code for i in analyse_urls(email)}
