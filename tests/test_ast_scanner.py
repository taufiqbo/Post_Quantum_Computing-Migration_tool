"""Tests for the AST scanner: does it see through nicknames?"""

from pqc_scanner.ast_scanner import scan_python
from pqc_scanner.rules import load_rules

RULES = load_rules()


def ids_by_line(findings):
    """Turn findings into {line_number: [rule ids]} so tests are easy to read."""
    result = {}
    for f in findings:
        result.setdefault(f.line, []).append(f.rule_id)
    return result


def test_follows_import_alias():
    code = (
        "from cryptography.hazmat.primitives.asymmetric import rsa as r\n"
        "key = r.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    findings = scan_python(code, "app.py", RULES)
    assert ids_by_line(findings) == {1: ["RSA"], 2: ["RSA"]}
    assert findings[1].confidence == "high"      # a real call
    assert findings[0].confidence == "medium"    # only an import


def test_reads_rsa_key_size():
    code = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
    )
    findings = scan_python(code, "app.py", RULES)
    assert "key_size=1024" in findings[1].detail
    assert "below 2048" in findings[1].detail


def test_finds_hash_inside_another_call():
    code = (
        "from cryptography.hazmat.primitives import hashes\n"
        "digest = hashes.Hash(hashes.SHA1())\n"
    )
    findings = scan_python(code, "app.py", RULES)
    assert ids_by_line(findings) == {2: ["SHA1"]}


def test_ignores_safe_code():
    code = "import hashlib\nh = hashlib.sha3_256(b'data')\n"
    assert scan_python(code, "app.py", RULES) == []


def test_comments_are_invisible_to_ast():
    # The AST throws comments away. (The regex scanner still reports them as low.)
    code = "# key = rsa.generate_private_key(65537, 1024)\n"
    assert scan_python(code, "app.py", RULES) == []


def test_broken_python_returns_none():
    # Not valid Python: the AST can't read it, so the caller falls back to regex
    assert scan_python("def broken(:\n", "bad.py", RULES) is None