"""Tests for the pqc-scan command-line options."""

from pathlib import Path

from pqc_scanner.cli import main

SAMPLES = str(Path(__file__).parent.parent / "samples")


def last_line(capsys):
    """The 'Scanned N files...' line printed by main()."""
    lines = capsys.readouterr().out.strip().splitlines()
    return next(line for line in lines if line.startswith("Scanned"))


def test_scan_samples(capsys):
    assert main([SAMPLES, "--quiet"]) == 0
    assert last_line(capsys) == ("Scanned 10 files: 37 quantum-vulnerable findings, "
                                 "3 quantum-safe findings.")


def test_exclude_a_folder(capsys):
    main([SAMPLES, "--quiet", "--exclude", "certs"])
    assert last_line(capsys).startswith("Scanned 7 files: 33 quantum-vulnerable")


def test_min_confidence_hides_medium_findings(capsys):
    main([SAMPLES, "--quiet", "--min-confidence", "high"])
    assert "32 quantum-vulnerable" in last_line(capsys)


def test_writes_html_report(tmp_path, capsys):
    report = tmp_path / "out" / "report.html"   # the "out" folder doesn't exist yet
    main([SAMPLES, "--quiet", "--html", str(report)])
    assert "Readiness score" in report.read_text(encoding="utf-8")


def test_missing_folder_returns_error_code(capsys):
    assert main(["no_such_folder"]) == 2
