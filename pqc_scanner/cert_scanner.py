"""Scanner #4: X.509 certificates (.pem, .crt, .cer, .der files).

A certificate is a signed ID card for a server or person. Two parts of it matter:

  1. The PUBLIC KEY inside it (RSA, ECDSA, ML-DSA, ...): which algorithm the
     server proves its identity with.
  2. The SIGNATURE on it (e.g. sha1WithRSAEncryption): how the issuer signed it.

Each algorithm has an official ID number called an OID, like 1.2.840.113549.1.1.1
for RSA. We read the OIDs from the certificate and look them up in the rules'
cert_oids lists.
"""

import re
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .models import Finding

CERT_EXTENSIONS = (".pem", ".crt", ".cer", ".der")

# Finds each certificate inside a PEM file (one file can hold a whole chain)
PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)

# NIST IR 8547: RSA and ECC are disallowed after 2035
NIST_CUTOFF_YEAR = 2035

# A certificate key is used for SIGNATURES, so the fix is a PQ signature
# algorithm, not ML-KEM (which is for key exchange).
SIGNATURE_FIX = ("ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) certificate, "
                 "once your certificate authority and clients support it.")


def is_cert_file(name):
    """Does this file name look like a certificate file?"""
    return name.lower().endswith(CERT_EXTENSIONS)


def load_certs(data):
    """Return a list of (line_number, certificate) found in the file's bytes."""
    certs = []
    if b"-----BEGIN" in data:
        # PEM: text with base64 blocks. Find every certificate block.
        for match in PEM_CERT_RE.finditer(data):
            line_number = data.count(b"\n", 0, match.start()) + 1
            try:
                certs.append((line_number, x509.load_pem_x509_certificate(match.group())))
            except ValueError:
                pass   # a damaged block: skip it
    else:
        # DER: raw binary, exactly one certificate
        try:
            certs.append((1, x509.load_der_x509_certificate(data)))
        except ValueError:
            pass   # not a certificate after all
    return certs


def key_details(cert):
    """Describe the public key, e.g. 'RSA 1024-bit' or 'EC secp384r1'."""
    try:
        key = cert.public_key()
    except Exception:
        return ""   # a key type this version of cryptography can't open
    if isinstance(key, rsa.RSAPublicKey):
        note = f"RSA {key.key_size}-bit"
        if key.key_size < 2048:
            note += " (below 2048 bits: weak even without a quantum computer)"
        return note
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}"
    return ""


def expiry_details(cert, rule):
    """Say when the certificate expires, and warn if that is past NIST's cut-off."""
    expires = cert.not_valid_after_utc
    note = f"expires {expires:%Y-%m-%d}"
    if expires < datetime.now(timezone.utc):
        note += " (ALREADY EXPIRED)"
    elif not rule.quantum_safe and expires.year > NIST_CUTOFF_YEAR:
        note += f" (after {NIST_CUTOFF_YEAR}, when NIST disallows RSA and ECC)"
    return note


def find_rule(oid, rules):
    """Return the rule whose cert_oids contain this OID, or None."""
    for rule in rules:
        if oid in rule.cert_oids:
            return rule
    return None


def scan_cert(path, rel_path, rules):
    """Return a list of Findings for one certificate file."""
    try:
        data = path.read_bytes()
    except OSError as err:
        print(f"  could not read {path}: {err}", file=sys.stderr)
        return []

    findings = []
    for line_number, cert in load_certs(data):
        subject = cert.subject.rfc4514_string() or "(no subject)"

        # 1. The public key inside the certificate
        key_rule = find_rule(cert.public_key_algorithm_oid.dotted_string, rules)
        if key_rule:
            parts = [key_details(cert), expiry_details(cert, key_rule)]
            findings.append(make_finding(
                key_rule, rel_path, line_number, subject,
                detail="public key: " + ", ".join(p for p in parts if p),
                replacement=key_rule.replacement if key_rule.quantum_safe else SIGNATURE_FIX,
            ))

        # 2. How the certificate was signed (e.g. sha1WithRSAEncryption = SHA-1).
        #    Skip it if it's the same rule as the key (an ML-DSA cert signed with ML-DSA).
        sig_rule = find_rule(cert.signature_algorithm_oid.dotted_string, rules)
        if sig_rule and sig_rule is not key_rule:
            findings.append(make_finding(
                sig_rule, rel_path, line_number, subject,
                detail=f"signed with {sig_rule.name}",
                replacement=(sig_rule.replacement if sig_rule.quantum_safe
                             else "Re-issue the certificate signed with SHA-256 or stronger."),
            ))
    return findings


def make_finding(rule, rel_path, line_number, subject, detail, replacement):
    return Finding(
        rule_id=rule.id,
        algorithm=rule.name,
        severity=rule.severity,
        file=rel_path,
        line=line_number,
        snippet=f"certificate {subject}"[:120],
        confidence="high",
        replacement=replacement,
        quantum_safe=rule.quantum_safe,
        detail=detail,
    )