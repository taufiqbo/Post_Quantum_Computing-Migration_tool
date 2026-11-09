"""Turn a list of Findings into a score, a summary, and JSON / CSV / HTML reports."""

import csv
import json
from collections import Counter
from dataclasses import asdict, fields
from datetime import datetime, timezone
from html import escape

from .models import Finding

# How "ready" a file is, judged by the worst thing found in it
FILE_SCORE = {"critical": 0, "high": 40, "medium": 70, "low": 90}

SEVERITIES = ["critical", "high", "medium", "low", "info"]
COLOURS = {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
           "low": "#3498db", "info": "#27ae60"}


# ---------------------------------------------------------------- the numbers

def readiness_score(findings, files_scanned):
    """Quantum-readiness score from 0 (not ready) to 100 (ready).

    Every scanned file starts at 100. A file's score drops to match its WORST
    quantum-vulnerable finding (a critical finding makes it 0). The overall
    score is the average over all files. Low-confidence findings (comments)
    don't count, because a comment is not real crypto.
    """
    if files_scanned == 0:
        return 100
    worst = {}   # file name -> lowest score seen so far
    for f in findings:
        if f.quantum_safe or f.confidence == "low":
            continue
        worst[f.file] = min(worst.get(f.file, 100), FILE_SCORE[f.severity])
    clean_files = files_scanned - len(worst)
    total = 100 * clean_files + sum(worst.values())
    return round(total / files_scanned)


def grade(score):
    """Turn a score into a school-style grade."""
    for limit, letter in [(90, "A"), (75, "B"), (50, "C"), (25, "D")]:
        if score >= limit:
            return letter
    return "F"


def summarise(findings, files_scanned):
    """Everything the reports need, in one dictionary."""
    vulnerable = [f for f in findings if not f.quantum_safe]
    score = readiness_score(findings, files_scanned)
    return {
        "files_scanned": files_scanned,
        "vulnerable": len(vulnerable),
        "quantum_safe": len(findings) - len(vulnerable),
        "score": score,
        "grade": grade(score),
        "by_severity": {s: sum(1 for f in vulnerable if f.severity == s) for s in SEVERITIES[:4]},
        "by_algorithm": dict(Counter(f.algorithm for f in vulnerable).most_common()),
    }


# ---------------------------------------------------------------- JSON and CSV

def write_json(findings, files_scanned, path):
    data = {
        "tool": "pqc-scan",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarise(findings, files_scanned),
        "findings": [asdict(f) for f in findings],   # dataclass -> dictionary
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_csv(findings, path):
    columns = [field.name for field in fields(Finding)]   # same order as models.py
    # newline="" stops Windows from adding a blank line between rows
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for f in findings:
            writer.writerow(asdict(f))


# ---------------------------------------------------------------- HTML

def bar_chart(counts, colour_for):
    """A simple bar chart made of <div>s: no JavaScript library needed."""
    biggest = max(counts.values(), default=0) or 1
    rows = []
    for label, count in counts.items():
        width = round(100 * count / biggest)
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{escape(label)}</span>'
            f'<span class="track"><span class="bar" style="width:{width}%;'
            f'background:{colour_for(label)}"></span></span>'
            f'<span class="bar-count">{count}</span></div>')
    return "\n".join(rows)


def write_html(findings, files_scanned, path):
    s = summarise(findings, files_scanned)
    score_colour = "#27ae60" if s["score"] >= 75 else "#e67e22" if s["score"] >= 50 else "#c0392b"

    # One table row per finding. escape() matters: snippets come from the files
    # we scanned, and a file could contain "<script>". Without escape(), opening
    # the report would run that script (an XSS attack on whoever reads it).
    rows = []
    for f in findings:
        rows.append(
            f'<tr data-severity="{f.severity}">'
            f'<td><span class="pill" style="background:{COLOURS[f.severity]}">{f.severity}</span></td>'
            f"<td>{escape(f.algorithm)}</td>"
            f'<td class="where"><code>{escape(f.file)}:{f.line}</code></td>'
            f"<td><code>{escape(f.snippet)}</code><div class=\"detail\">{escape(f.detail)}</div></td>"
            f"<td>{f.confidence}</td>"
            f"<td>{escape(f.replacement)}</td></tr>")

    severity_chart = bar_chart(s["by_severity"], lambda sev: COLOURS[sev])
    algorithm_chart = bar_chart(s["by_algorithm"], lambda _: "#34495e")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    page = HTML_TEMPLATE.format(
        score=s["score"], grade=s["grade"], score_colour=score_colour,
        files=s["files_scanned"], vulnerable=s["vulnerable"], safe=s["quantum_safe"],
        severity_chart=severity_chart, algorithm_chart=algorithm_chart,
        rows="\n".join(rows), generated=generated)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)


# The page itself. {{ and }} are literal braces (needed for CSS and JavaScript),
# while {score}, {rows} etc. are filled in by .format() above.
HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQC Readiness Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #f4f6f8; color: #222; }}
  header {{ background: #1f2d3d; color: white; padding: 24px 32px; }}
  header h1 {{ margin: 0 0 4px; font-size: 24px; }}
  main {{ padding: 24px 32px; max-width: 1200px; margin: auto; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 10px; padding: 16px 20px; flex: 1; min-width: 160px;
           box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  .big {{ font-size: 40px; font-weight: bold; }}
  .charts {{ display: flex; gap: 16px; flex-wrap: wrap; margin-top: 16px; }}
  .charts .card {{ min-width: 300px; }}
  .bar-row {{ display: flex; align-items: center; gap: 8px; margin: 6px 0; }}
  .bar-label {{ flex: 0 0 190px; font-size: 14px; }}
  .track {{ flex: 1; }}
  .bar {{ display: block; height: 16px; border-radius: 4px; min-width: 2px; }}
  .bar-count {{ flex: 0 0 30px; font-size: 14px; }}
  .filters {{ margin: 24px 0 8px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .filters input, .filters select {{ padding: 8px; font-size: 14px; }}
  table {{ width: 100%; border-collapse: collapse; background: white; font-size: 14px; }}
  th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }}
  th {{ background: #ecf0f1; }}
  code {{ font-size: 12px; word-break: break-all; }}
  .where code {{ white-space: nowrap; word-break: normal; }}
  .detail {{ color: #666; font-size: 12px; margin-top: 4px; }}
  .pill {{ color: white; border-radius: 10px; padding: 2px 8px; font-size: 12px; }}
</style>
</head>
<body>
<header>
  <h1>Post-Quantum Cryptography Readiness Report</h1>
  <div>Generated {generated} by pqc-scan</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div>Readiness score</div>
      <div class="big" style="color:{score_colour}">{score}/100 ({grade})</div></div>
    <div class="card"><div>Files scanned</div><div class="big">{files}</div></div>
    <div class="card"><div>Quantum-vulnerable findings</div><div class="big">{vulnerable}</div></div>
    <div class="card"><div>Quantum-safe findings</div><div class="big">{safe}</div></div>
  </div>

  <div class="charts">
    <div class="card"><h3>By severity</h3>{severity_chart}</div>
    <div class="card"><h3>By algorithm</h3>{algorithm_chart}</div>
  </div>

  <div class="filters">
    <input id="search" placeholder="Search file, algorithm, code..." size="40">
    <select id="severity">
      <option value="">All severities</option>
      <option>critical</option><option>high</option><option>medium</option>
      <option>low</option><option>info</option>
    </select>
  </div>

  <table>
    <thead><tr><th>Severity</th><th>Algorithm</th><th>Location</th><th>Evidence</th>
               <th>Confidence</th><th>Fix</th></tr></thead>
    <tbody id="rows">
{rows}
    </tbody>
  </table>
</main>
<script>
  // Hide the table rows that don't match the search box and the severity dropdown
  function applyFilters() {{
    const text = document.getElementById("search").value.toLowerCase();
    const severity = document.getElementById("severity").value;
    for (const row of document.querySelectorAll("#rows tr")) {{
      const matchesText = row.textContent.toLowerCase().includes(text);
      const matchesSeverity = !severity || row.dataset.severity === severity;
      row.style.display = matchesText && matchesSeverity ? "" : "none";
    }}
  }}
  document.getElementById("search").addEventListener("input", applyFilters);
  document.getElementById("severity").addEventListener("change", applyFilters);
</script>
</body>
</html>
"""
