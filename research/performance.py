"""Local performance measurement.

Measures wall-clock time per pipeline stage and peak Python memory for batches
of 1, 10 and 100 messages, on THIS machine. Nothing here supports a claim about
behaviour at larger scale; only the sizes measured are reported.

Method
------
* Each batch size is run REPEATS times; the median is reported with min/max so
  run-to-run variation is visible.
* The spaCy model load is a one-off per process and is measured separately,
  then excluded from the per-batch timings (a warm-up call is made first).
* Stage timings call the same functions the pipeline calls, in the same order.
* Peak memory is measured with tracemalloc (Python allocations only; native
  allocations inside spaCy/numpy are not counted).
* Intelligence and correlation are disabled to measure the engine itself.

Inputs are the first N messages of the synthetic research train split.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from bec_detector.acquisition import load_bytes
from bec_detector.analysis import (
    analyse_attachments,
    analyse_sender,
    analyse_text,
    analyse_urls,
)
from bec_detector.analysis.text import _load_nltk, _load_spacy
from bec_detector.forensics import IOCStore, NullThreatIntelProvider
from bec_detector.pipeline import BECPipeline
from bec_detector.report import render_html
from bec_detector.report.assemble import assemble_report
from bec_detector.validation import fuse

SOURCE = Path("data") / "research" / "train"
RESULTS_DIR = Path("output") / "research"
SIZES = (1, 10, 100)
REPEATS = 3


def _inputs(n: int) -> list[bytes]:
    files = sorted(SOURCE.glob("*.eml"))[:n]
    if len(files) < n:
        raise FileNotFoundError("research corpus absent - run data/build_research_corpus.py")
    return [f.read_bytes() for f in files]


def _timed(fn: Callable[[], Any]) -> tuple[float, Any]:
    start = time.perf_counter()
    result = fn()
    return time.perf_counter() - start, result


def run_once(raws: list[bytes]) -> dict[str, float]:
    stages: dict[str, float] = {}
    with tempfile.TemporaryDirectory() as tmp:
        pipeline = BECPipeline(case_id="CASE-PERF", intel=NullThreatIntelProvider(),
                               ioc_store=IOCStore(Path(tmp) / "i.json"), correlate=False)

        stages["parse"], emails = _timed(
            lambda: [load_bytes(r, f"m{i}") for i, r in enumerate(raws)])
        stages["baseline"], _ = _timed(lambda: pipeline.fit(emails))

        # Component timings, same functions and order as BECPipeline.assess.
        stages["sender_and_auth"], _ = _timed(lambda: [analyse_sender(e) for e in emails])
        stages["nlp"], _ = _timed(lambda: [analyse_text(e) for e in emails])
        stages["behaviour_thread_style"], _ = _timed(lambda: [
            (pipeline.baseline.analyse(e), pipeline.threads.analyse(e), pipeline.style.analyse(e))
            for e in emails])
        stages["url_and_attachment"], _ = _timed(
            lambda: [(analyse_urls(e), analyse_attachments(e)) for e in emails])

        indicator_sets = [analyse_sender(e) + analyse_text(e) for e in emails]
        stages["fusion"], _ = _timed(
            lambda: [fuse(e, list(ind)) for e, ind in zip(emails, indicator_sets)])

        # Full assessment (all of the above plus IOCs, ATT&CK mapping, timeline).
        stages["assess_total"], assessments = _timed(
            lambda: [pipeline.assess(e) for e in emails])

        stages["report_assemble"], report = _timed(
            lambda: assemble_report(pipeline, assessments))
        stages["report_render_html"], _ = _timed(lambda: render_html(report))

    stages["end_to_end"] = (stages["parse"] + stages["baseline"] + stages["assess_total"]
                            + stages["report_assemble"] + stages["report_render_html"])
    return stages


def measure() -> dict[str, Any]:
    load_spacy_s, _ = _timed(_load_spacy)
    load_nltk_s, _ = _timed(_load_nltk)
    run_once(_inputs(2))  # warm-up so lazy imports are not billed to the first batch

    batches = []
    for n in SIZES:
        raws = _inputs(n)
        runs = [run_once(raws) for _ in range(REPEATS)]

        tracemalloc.start()
        run_once(raws)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        stage_stats = {}
        for stage in runs[0]:
            values = [r[stage] for r in runs]
            stage_stats[stage] = {
                "median_s": round(statistics.median(values), 4),
                "min_s": round(min(values), 4),
                "max_s": round(max(values), 4),
            }
        median_total = stage_stats["end_to_end"]["median_s"]
        batches.append({
            "messages": n,
            "input_bytes": sum(len(r) for r in raws),
            "stages": stage_stats,
            "per_message_end_to_end_ms": round(median_total / n * 1000, 1),
            "throughput_messages_per_s": round(n / median_total, 1) if median_total else None,
            "peak_python_memory_mb": round(peak / 1024 / 1024, 1),
        })

    return {
        "result_type": "LOCAL PERFORMANCE MEASUREMENT",
        "scope": f"Batches of {', '.join(map(str, SIZES))} messages on one machine. "
                 "No claim is made about larger batches or other hardware.",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "machine": {
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "cpu_count": os.cpu_count(),
            "python": sys.version.split()[0],
        },
        "method": {
            "repeats": REPEATS, "statistic": "median (min/max shown)",
            "intel": "disabled", "correlation": "disabled",
            "memory": "tracemalloc peak - Python allocations only",
            "input": str(SOURCE),
        },
        "one_off_model_load_s": {"spacy": round(load_spacy_s, 3), "nltk": round(load_nltk_s, 3)},
        "batches": batches,
    }


def main() -> int:
    print("LOCAL PERFORMANCE - this machine only\n")
    r = measure()
    print(f"machine: {r['machine']['platform']}, {r['machine']['cpu_count']} CPUs, "
          f"Python {r['machine']['python']}")
    print(f"one-off model load: spaCy {r['one_off_model_load_s']['spacy']}s, "
          f"NLTK {r['one_off_model_load_s']['nltk']}s\n")
    stages = list(r["batches"][0]["stages"])
    print(f"{'stage (median s)':<26}" + "".join(f"{b['messages']:>10}" for b in r["batches"]))
    for stage in stages:
        print(f"{stage:<26}" + "".join(f"{b['stages'][stage]['median_s']:>10.3f}" for b in r["batches"]))
    print(f"{'per message e2e (ms)':<26}" + "".join(f"{b['per_message_end_to_end_ms']:>10.1f}" for b in r["batches"]))
    print(f"{'peak Python memory (MB)':<26}" + "".join(f"{b['peak_python_memory_mb']:>10.1f}" for b in r["batches"]))
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "performance.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    print(f"\nwritten: {RESULTS_DIR / 'performance.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
