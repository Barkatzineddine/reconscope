"""Render a :class:`~reconscope.models.ScanReport` as JSON or as a self-contained HTML page.

The HTML report is meant to be opened straight from disk and shared, so it is hardened: every
value is HTML-escaped by Jinja's autoescaping, and a Content Security Policy forbids scripts,
remote resources and form submissions. The only inline style is allowed by its SHA-256 hash,
computed here from the exact stylesheet text, so a collected value can never introduce a
second style or script block.
"""

from __future__ import annotations

import base64
import hashlib
import json
from importlib import resources

from jinja2 import Environment, select_autoescape

from .models import ScanReport, to_jsonable

# The report's entire stylesheet. Kept as one constant so its hash (used in the CSP) is computed
# over exactly the bytes that appear inside the <style> element.
REPORT_CSS = """
:root { color-scheme: light dark; --bg:#0f1117; --fg:#e6e6e6; --muted:#8a94a7; --card:#171a23;
  --line:#2a2f3a; --accent:#4fd1c5; }
* { box-sizing: border-box; }
body { margin:0; padding:1.5rem; background:var(--bg); color:var(--fg);
  font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
h1 { margin:0; font-size:1.4rem; color:var(--accent); }
h2 { font-size:1.1rem; border-bottom:1px solid var(--line); padding-bottom:.3rem; }
.sub,.meta,.muted { color:var(--muted); }
.auth { background:var(--card); border:1px solid var(--line); border-left:3px solid var(--accent);
  padding:.6rem .8rem; border-radius:6px; }
section { margin:1.4rem 0; }
.counts { display:flex; flex-wrap:wrap; gap:.4rem; margin-bottom:.4rem; }
.pill { display:inline-block; padding:.08rem .5rem; border-radius:999px; font-size:.8rem;
  border:1px solid var(--line); }
.sev-high { background:#5b1a1a; color:#ffd7d7; border-color:#7a2a2a; }
.sev-medium { background:#5b421a; color:#ffe6c7; border-color:#7a5a2a; }
.sev-low { background:#1a3b5b; color:#cfe6ff; border-color:#2a567a; }
.sev-info { background:#1f2733; color:#cfd7e6; }
table { width:100%; border-collapse:collapse; margin:.6rem 0; background:var(--card);
  border:1px solid var(--line); border-radius:6px; overflow:hidden; }
caption { text-align:left; color:var(--muted); padding:.3rem 0; }
th,td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line);
  vertical-align:top; word-break:break-word; }
thead th { color:var(--accent); }
.state-open { color:#8be28b; }
.details pre { margin:0; white-space:pre-wrap; color:var(--muted); font-size:.82rem; }
.finding { margin:.3rem 0; }
footer { margin-top:2rem; color:var(--muted); font-size:.82rem; border-top:1px solid var(--line);
  padding-top:.8rem; }
@media (max-width:600px){ body{padding:1rem;} th,td{padding:.35rem .4rem; font-size:.85rem;} }
"""


def to_json(report: ScanReport) -> str:
    """Serialise the report as pretty-printed JSON."""

    return json.dumps(to_jsonable(report), indent=2, sort_keys=False, ensure_ascii=False)


def _style_hash() -> str:
    digest = hashlib.sha256(REPORT_CSS.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def _timestamp(value: object) -> str:
    return str(value) if value is not None else "in progress"


def to_html(report: ScanReport) -> str:
    """Render the hardened, self-contained HTML report."""

    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template_text = (
        resources.files("reconscope.templates").joinpath("report.html.j2").read_text(encoding="utf-8")
    )
    template = env.from_string(template_text)
    return template.render(
        report=report,
        css=REPORT_CSS,
        style_hash=_style_hash(),
        counts=report.finding_counts(),
        started=_timestamp(report.started_at),
        finished=_timestamp(report.finished_at),
    )
