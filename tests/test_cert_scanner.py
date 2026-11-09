"""Tests for the certificate scanner."""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pqc_scanner.cert_scanner import is_cert_file, scan_cert
from pqc_scanner.rules import load_rules

RULES = load_rules()
CERTS = Path(__file__).parent.parent / "samples" / "certs"


def ids(findings):
    return sorted(f.rule_id for f in findings)


def test_is_cert_file():
    assert is_cert_file("server.pem")
    assert is_cert_file("site.CRT")
    assert is_cert_file("root.der")
    assert not is_cert_file("nginx.conf")


# ---- things it MUST find ----

def test_old_cert_rsa_1024_and_sha1():
    findings = scan_cert(CERTS / "legacy_sha1.crt", "legacy_sha1.crt", RULES)
    assert ids(findings) == ["RSA", "SHA1"]
    rsa = [f for f in findings if f.rule_id == "RSA"][0]
    assert "1024-bit" in rsa.detail
    assert "EXPIRED" in rsa.detail


def test_chain_reports_each_certificate_on_its_own_line():
    findings = scan_cert(CERTS / "chain.pem", "chain.pem", RULES)
    assert [(f.rule_id, f.line) for f in findings] == [("RSA", 1), ("ECC", 15)]
    assert "after 2035" in findings[0].detail


def test_mldsa_cert_is_quantum_safe():
    findings = scan_cert(CERTS / "pq_mldsa.pem", "pq_mldsa.pem", RULES)
    assert ids(findings) == ["ML-DSA"]
    assert findings[0].quantum_safe


def test_binary_der_cert(tmp_path):
    # Same certificate as legacy_sha1.crt, but saved in binary (DER) format
    cert = x509.load_pem_x509_certificate((CERTS / "legacy_sha1.crt").read_bytes())
    der_file = tmp_path / "legacy.der"
    der_file.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    assert ids(scan_cert(der_file, "legacy.der", RULES)) == ["RSA", "SHA1"]


# ---- things it must NOT flag ----

def test_file_that_is_not_a_certificate(tmp_path):
    fake = tmp_path / "notes.pem"
    fake.write_text("this is not a certificate\n", encoding="utf-8")
    assert scan_cert(fake, "notes.pem", RULES) == []