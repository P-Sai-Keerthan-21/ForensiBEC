"""Stage 4 - Report.

Renders assessments as machine-readable JSON and as an examiner-facing HTML
report carrying the chain-of-custody record and per-indicator evidence.
"""

from .builder import build_case_report, write_json
from .html import render_html

__all__ = ["build_case_report", "write_json", "render_html"]
