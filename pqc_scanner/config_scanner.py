"""Scanner #3: server crypto settings in nginx, Apache, OpenSSH and OpenSSL config files.

Config files list algorithms as tokens joined by : or , like this:

    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA;      (nginx)
    KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1      (OpenSSH)

So instead of regex over whole lines, we:
  1. find the lines that set crypto (the "directives" below),
  2. split the value into tokens,
  3. match each token against the rules' config_tokens.
"""

import re

from .models import Finding

# Directive names (lower case) that hold crypto settings, and which software uses them
CRYPTO_DIRECTIVES = {
    # nginx
    "ssl_ciphers": "nginx", "ssl_ecdh_curve": "nginx", "ssl_protocols": "nginx",
    # Apache httpd
    "sslciphersuite": "apache", "sslprotocol": "apache", "sslopensslconfcmd": "apache",
    # OpenSSH
    "kexalgorithms": "ssh", "hostkeyalgorithms": "ssh", "pubkeyacceptedalgorithms": "ssh",
    "ciphers": "ssh", "macs": "ssh", "hostkey": "ssh",
    # OpenSSL openssl.cnf
    "default_md": "openssl", "cipherstring": "openssl", "groups": "openssl",
}

CONFIG_FILENAMES = {"sshd_config", "ssh_config", "nginx.conf", "httpd.conf", "openssl.cnf"}

# "name value" or "name = value"
DIRECTIVE_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*(?:=\s*|\s+)(.*)$")

# Characters that separate tokens: spaces, commas, colons, semicolons, plus signs, quotes
TOKEN_SPLIT = re.compile(r"[\s,:;+\"']+")


def is_config_file(name):
    """Does this file name look like a server config file?"""
    lower = name.lower()
    return (lower in CONFIG_FILENAMES
            or lower.endswith((".conf", ".cnf"))
            or lower.startswith("sshd_config"))


def tokens(value):
    """Split a directive's value into tokens, skipping disabled ones."""
    for token in TOKEN_SPLIT.split(value):
        if not token or token.startswith(("!", "-")):
            continue   # "!MD5" and "-3des-cbc" mean "turn this OFF"
        yield token


def scan_config(text, rel_path, rules):
    """Return a list of Findings for one config file."""
    findings = []
    safe_rules = [r for r in rules if r.quantum_safe]
    vulnerable_rules = [r for r in rules if not r.quantum_safe]

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()      # drop comments
        match = DIRECTIVE_RE.match(line)
        if not match:
            continue
        directive = match.group(1).lower()
        value = match.group(2).rstrip(";").strip()     # nginx lines end with ;
        if directive not in CRYPTO_DIRECTIVES:
            continue   # e.g. "listen 443" or "Port 22": nothing to do with crypto
        software = CRYPTO_DIRECTIVES[directive]

        found_on_this_line = set()
        for token in tokens(value):
            # 1. Quantum-safe or hybrid (e.g. X25519MLKEM768)? Good news, and we do
            #    NOT also flag its classical half (X25519) as vulnerable.
            safe = find_rule(token, safe_rules)
            if safe:
                add(findings, found_on_this_line, safe, rel_path, line_number,
                    raw_line, f"{software} {directive}: {token}")
                continue
            # 2. Otherwise, which vulnerable algorithms does this token use?
            #    One token can use several: ECDHE-RSA-AES128-SHA = ECC + RSA + SHA-1
            for rule in vulnerable_rules:
                if any(pattern.search(token) for pattern in rule.config_tokens):
                    add(findings, found_on_this_line, rule, rel_path, line_number,
                        raw_line, f"{software} {directive}: {token}")
    return findings


def find_rule(token, rules):
    """Return the first rule whose config_tokens match this token, or None."""
    for rule in rules:
        if any(pattern.search(token) for pattern in rule.config_tokens):
            return rule
    return None


def add(findings, found_on_this_line, rule, rel_path, line_number, raw_line, detail):
    """Add a finding, but only once per rule per line."""
    if rule.id in found_on_this_line:
        return
    found_on_this_line.add(rule.id)
    findings.append(Finding(
        rule_id=rule.id,
        algorithm=rule.name,
        severity=rule.severity,
        file=rel_path,
        line=line_number,
        snippet=raw_line.strip()[:120],
        confidence="high",
        replacement=rule.replacement,
        quantum_safe=rule.quantum_safe,
        detail=detail,
    ))