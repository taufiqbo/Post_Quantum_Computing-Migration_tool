# Learning Log

## Lesson 1: Project setup and detection rules (2026-11-05)

**What the tool does**
This is a post-quantum cryptography (PQC) migration scanner. It scans code, server configs and certificates to find old classical crypto (RSA, ECC, Diffie-Hellman, DSA, SHA-1, MD5, 3DES) that is still in use, and recommends the NIST quantum-safe replacement.

**Why it matters: "harvest now, decrypt later" (HNDL)**
Attackers can record encrypted traffic and data today and store it. When a large quantum computer exists, Shor's algorithm can break the RSA/ECC key exchange that protected it, and they can decrypt everything they saved. That is why key exchange is rated critical even before quantum computers are ready.

**What I built**
- Project setup: GitHub repo, Python virtual environment, requirements.txt, .gitignore
- `rules/algorithms.yaml`: the rule set. Each rule has a severity, an HNDL flag, the quantum threat, the NIST replacement and regex patterns to detect it in code
- `rules.py`: loads the YAML rules into Python objects and pre-compiles the regexes

**NIST post-quantum standards**
- ML-KEM (FIPS 203): key exchange, agreeing on a shared secret key. Replaces RSA/ECDH/DH key exchange.
- ML-DSA (FIPS 204): digital signatures. Replaces RSA/ECDSA signatures.
- SLH-DSA (FIPS 205): hash-based digital signatures. A backup in case lattice-based crypto is ever broken.

**Challenges**
The hardest part was writing correct rules and understanding whether each rule made sense for a scanner: which severity to give it, whether HNDL applies, and writing regexes that match real code. I also had to fix YAML indentation errors and a regex typo (`\g`) that crashed Python.
