# Performance

**Result type: local measurement on one machine.** These figures describe
batches of 1, 10 and 100 messages on the hardware below. They support no claim
about larger batches, other hardware, or concurrent users, and none is made.

Reproduce:

```bash
venv\Scripts\python.exe -m research.performance
```

Output: `output/research/performance.json`, which records the machine, the
method and every stage's median, minimum and maximum.

## 1. Method

| Setting | Value |
|---|---|
| Machine | Windows 11 (10.0.26200), Intel64 Family 6 Model 154, 20 logical CPUs |
| Python | 3.14.3 |
| Input | First *N* messages of the synthetic research train split (`data/research/train`) |
| Repeats | 3 per batch size; **median** reported, min/max in the JSON |
| Model loading | spaCy and NLTK are loaded once and timed separately; a warm-up batch runs first |
| Memory | `tracemalloc` peak, **Python allocations only** (native memory in spaCy/numpy is not counted) |
| Intelligence / correlation | Disabled, so the figures describe the engine rather than I/O on the IOC store |

Stage timings call the same functions `BECPipeline.assess` calls, in the same
order. `assess_total` is the full per-message assessment (all analysers, IOC
extraction, ATT&CK mapping, timeline). `end_to_end` is parse + baseline +
assessment + report assembly + HTML rendering.

## 2. Results

One-off model load per process: **spaCy 1.26 s, NLTK 7.11 s**. The NLTK figure
is the import plus reading the WordNet corpus from local disk; nothing is
downloaded.

| Stage (median seconds) | 1 message | 10 messages | 100 messages |
|---|---|---|---|
| Parse (including SHA-256) | 0.006 | 0.062 | 0.601 |
| Baseline fit (pass 1) | 0.000 | 0.001 | 0.010 |
| Sender and authentication | 0.002 | 0.018 | 0.129 |
| NLP (spaCy NER, lexicons, lemmatisation) | 0.018 | 0.325 | 3.013 |
| Behaviour, thread, stylometry | 0.000 | 0.001 | 0.054 |
| URL and attachment (static) | 0.000 | 0.000 | 0.001 |
| Fusion | 0.000 | 0.001 | 0.012 |
| **Assessment total** | 0.023 | 0.334 | 3.297 |
| Report assembly | 0.012 | 0.054 | 1.391 |
| HTML rendering | 0.002 | 0.009 | 0.089 |
| **End to end** | **0.042** | **0.462** | **5.394** |
| Per message, end to end | 42.1 ms | 46.2 ms | 53.9 ms |
| Peak Python memory | 0.7 MB | 2.2 MB | 20.9 MB |

Input sizes: 789 B, 8.9 KB and 84.9 KB. Run-to-run variation was small: the
100-message end-to-end time ranged from 5.32 to 5.42 s.

## 3. Interpretation

- **NLP dominates assessment.** About 90% of assessment time is spaCy named
  entity recognition and lexicon matching. Everything forensic (headers,
  authentication, behaviour, threads, style, URLs, fusion) takes under 0.25 s
  for 100 messages.
- **Report assembly grows faster than linearly.** It goes from 0.054 s at 10
  messages to 1.39 s at 100. Profiling at 100 messages attributes about 0.9 s
  to the evidence-graph layout (`networkx.spring_layout`, the
  Fruchterman-Reingold algorithm, which is quadratic in node count per
  iteration) and about 0.4 s to confusable-domain analysis for the report's
  domain table. For much larger cases the graph drawing is the first thing
  that would need to change, for example a static layout or omitting the
  drawing above a node limit. This has not been implemented or measured.
- **Per-message cost rises slightly with batch size** (42 → 54 ms) for the
  same reason.

## 4. What these figures do not show

- Behaviour beyond 100 messages. The graph layout's growth means the
  per-message figure should **not** be extrapolated.
- Web-server throughput or latency under concurrent requests. The dashboard is
  designed for a single analyst on localhost.
- Native memory use. `tracemalloc` does not see spaCy's or numpy's own
  allocations, so real process memory is higher than the peak shown.
- Other hardware or operating systems.
