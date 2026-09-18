"""Performance harness: measures what it says, and claims nothing beyond it."""

from __future__ import annotations

import pytest

from research import performance

pytestmark = pytest.mark.skipif(
    not performance.SOURCE.exists(), reason="research corpus not generated")


def test_run_once_reports_every_stage():
    stages = performance.run_once(performance._inputs(2))
    expected = {"parse", "baseline", "sender_and_auth", "nlp", "behaviour_thread_style",
                "url_and_attachment", "fusion", "assess_total", "report_assemble",
                "report_render_html", "end_to_end"}
    assert set(stages) == expected
    assert all(v >= 0 for v in stages.values())


def test_end_to_end_is_the_sum_of_its_parts():
    s = performance.run_once(performance._inputs(1))
    parts = s["parse"] + s["baseline"] + s["assess_total"] + s["report_assemble"] \
        + s["report_render_html"]
    assert s["end_to_end"] == pytest.approx(parts)


def test_scope_statement_disclaims_other_scales(monkeypatch):
    monkeypatch.setattr(performance, "SIZES", (1,))
    monkeypatch.setattr(performance, "REPEATS", 1)
    result = performance.measure()
    assert result["result_type"] == "LOCAL PERFORMANCE MEASUREMENT"
    assert "No claim is made about larger batches" in result["scope"]
    assert [b["messages"] for b in result["batches"]] == [1]
    assert result["method"]["intel"] == "disabled"


def test_asking_for_more_messages_than_exist_fails_loudly():
    with pytest.raises(FileNotFoundError):
        performance._inputs(10_000)
