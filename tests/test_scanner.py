"""Tests for the scanner: does it find what it should, and nothing it shouldn't?"""

from pathlib import Path

from pqc_scanner.rules import load_rules
from pqc_scanner.scanner import scan_file, scan_folder

RULES = load_rules()
SAMPLES = Path(__file__).parent.parent / "samples"


def scan_text(tmp_path, filename, code):
    """Helper: write `code` into a temporary file, scan it, return the findings."""
    path = tmp_path / filename
    path.write_text(code, encoding="utf-8")
    return scan_file(path, RULES, tmp_path)


def rule_ids(findings):
    return [f.rule_id for f in findings]


# ---- things the scanner MUST find (no false negatives) ----

def test_finds_python_rsa(tmp_path):
    findings = scan_text(tmp_path, "app.py", "key = rsa.generate_private_key(65537, 2048)\n")
    assert rule_ids(findings) == ["RSA"]
    assert findings[0].line == 1
    assert findings[0].confidence == "high"


def test_finds_java_rsa(tmp_path):
    findings = scan_text(tmp_path, "App.java", 'KeyPairGenerator.getInstance("RSA");\n')
    assert "RSA" in rule_ids(findings)


def test_finds_node_rsa(tmp_path):
    # This was the false negative fixed in Lesson 2
    findings = scan_text(tmp_path, "app.js", "crypto.generateKeyPairSync('rsa', {});\n")
    assert "RSA" in rule_ids(findings)


def test_finds_md5_and_sha1(tmp_path):
    code = "a = hashlib.md5(data)\nb = hashlib.sha1(data)\n"
    findings = scan_text(tmp_path, "hashes.py", code)
    assert sorted(rule_ids(findings)) == ["MD5", "SHA1"]

# ---- things the scanner must NOT flag (no false positives) ----

def test_ignores_safe_hash(tmp_path):
    findings = scan_text(tmp_path, "good.py", "h = hashlib.sha3_256(data)\n")
    assert findings == []


def test_quantum_safe_in_comment_is_ignored(tmp_path):
    findings = scan_text(tmp_path, "todo.js", "// TODO: move to ML-KEM\n")
    assert findings == []


def test_vulnerable_crypto_in_comment_is_low_confidence(tmp_path):
    findings = scan_text(tmp_path, "old.py", "# key = rsa.generate_private_key(65537, 1024)\n")
    assert rule_ids(findings) == ["RSA"]
    assert findings[0].confidence == "low"


def test_skips_venv_folder(tmp_path):
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "lib.py").write_text("hashlib.md5(x)\n", encoding="utf-8")
    findings, files_scanned = scan_folder(tmp_path, RULES)
    assert findings == []
    assert files_scanned == 0


# ---- the whole samples folder (a "regression test") ----

def test_samples_folder_gives_known_result():
    findings, files_scanned = scan_folder(SAMPLES, RULES)
    vulnerable = [f for f in findings if not f.quantum_safe]
    assert files_scanned == 10
    assert len(vulnerable) == 37
    assert findings[0].severity == "critical"  # sorted: most severe first

  
  