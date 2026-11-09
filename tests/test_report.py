"""Tests for the score and the JSON / CSV / HTML reports."""

import csv
import json

from pqc_scanner.models import Finding
from pqc_scanner.report import grade, readiness_score, write_csv, write_html, write_json


def finding(severity="critical", file="app.py", confidence="high", safe=False, snippet="x"):
    """Helper: make a Finding without typing all 10 fields every time."""
    return Finding(rule_id="RSA", algorithm="RSA", severity=severity, file=file, line=1,
                   snippet=snippet, confidence=confidence, replacement="ML-KEM",
                   quantum_safe=safe)


# ---- the score ----

def test_no_findings_is_100():
    assert readiness_score([], files_scanned=5) == 100


def test_score_uses_the_worst_finding_per_file():
    findings = [finding("critical", "a.py"), finding("medium", "a.py"), finding("high", "b.py")]
    # a.py -> 0 (worst is critical), b.py -> 40, two clean files -> 100 + 100
    assert readiness_score(findings, files_scanned=4) == round((0 + 40 + 100 + 100) / 4)


def test_safe_and_low_confidence_findings_do_not_lower_the_score():
    findings = [finding(safe=True), finding(confidence="low")]
    assert readiness_score(findings, files_scanned=1) == 100


def test_grades():
    assert grade(100) == "A"
    assert grade(75) == "B"
    assert grade(20) == "F"


# ---- the files ----

def test_json_and_csv(tmp_path):
    findings = [finding(), finding("high", "b.py")]
    write_json(findings, 2, tmp_path / "r.json")
    write_csv(findings, tmp_path / "r.csv")

    data = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert data["summary"]["vulnerable"] == 2
    assert data["findings"][0]["file"] == "app.py"

    with open(tmp_path / "r.csv", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["severity"] for r in rows] == ["critical", "high"]


def test_html_escapes_code_from_scanned_files(tmp_path):
    # A scanned file could contain HTML. It must show up as text, not run.
    evil = finding(snippet='<script>alert("hacked")</script>')
    write_html([evil], 1, tmp_path / "r.html")
    page = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert" in page
