"""Tests for the config scanner (nginx, Apache, OpenSSH, OpenSSL)."""

from pqc_scanner.config_scanner import is_config_file, scan_config
from pqc_scanner.rules import load_rules

RULES = load_rules()


def ids(findings):
    return sorted(f.rule_id for f in findings)


# ---- which files count as config files ----

def test_is_config_file():
    assert is_config_file("nginx.conf")
    assert is_config_file("sshd_config")
    assert is_config_file("openssl.cnf")
    assert is_config_file("site.conf")
    assert not is_config_file("app.py")
    assert not is_config_file("README.md")


# ---- things it MUST find ----

def test_one_cipher_suite_can_hold_several_algorithms():
    line = "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA;\n"
    findings = scan_config(line, "nginx.conf", RULES)
    assert ids(findings) == ["3DES", "DH", "ECC", "RSA", "SHA1"]


def test_ssh_key_exchange():
    findings = scan_config("KexAlgorithms diffie-hellman-group14-sha1\n", "sshd_config", RULES)
    assert ids(findings) == ["DH", "SHA1"]
    assert findings[0].detail == "ssh kexalgorithms: diffie-hellman-group14-sha1"


def test_hybrid_group_is_quantum_safe():
    findings = scan_config("ssl_ecdh_curve X25519MLKEM768;\n", "nginx.conf", RULES)
    assert ids(findings) == ["ML-KEM"]
    assert findings[0].quantum_safe


# ---- things it must NOT flag ----

def test_disabled_algorithms_are_ignored():
    findings = scan_config("ssl_ciphers !MD5:!aNULL:!DES-CBC3-SHA;\n", "nginx.conf", RULES)
    assert findings == []


def test_non_crypto_lines_are_ignored():
    findings = scan_config("listen 443 ssl;\nPort 22\n", "x.conf", RULES)
    assert findings == []


def test_commented_out_directive_is_ignored():
    findings = scan_config("# KexAlgorithms diffie-hellman-group1-sha1\n", "sshd_config", RULES)
    assert findings == []