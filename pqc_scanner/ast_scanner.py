"""Scanner #2: understand Python code with the AST instead of just matching text.

Regex only sees letters. The AST (Abstract Syntax Tree) is Python's own
"understanding" of the code, so we can follow imports and nicknames:

    from cryptography.hazmat.primitives.asymmetric import rsa as r
    key = r.generate_private_key(public_exponent=65537, key_size=2048)

Regex can't know that `r` means RSA. The AST scanner can.
"""

import ast

from .models import Finding


class CryptoVisitor(ast.NodeVisitor):
    """Walks through the tree and remembers every crypto import and call."""

    def __init__(self, rules):
        self.rules = rules
        self.aliases = {}   # nickname -> full name, e.g. "r" -> "cryptography...asymmetric.rsa"
        self.hits = []      # list of (line_number, rule, confidence, detail)

    # --- imports: learn the nicknames -------------------------------------

    def visit_Import(self, node):
        # import hashlib   /   import rsa as r
        for alias in node.names:
            nickname = alias.asname or alias.name
            self.aliases[nickname] = alias.name
            self.check(alias.name, node.lineno, "medium", f"imports {alias.name}")

    def visit_ImportFrom(self, node):
        # from cryptography.hazmat.primitives.asymmetric import rsa, ec
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}"
            nickname = alias.asname or alias.name
            self.aliases[nickname] = full
            self.check(full, node.lineno, "medium", f"imports {full}")

    # --- calls: something(...) --------------------------------------------

    def visit_Call(self, node):
        full = self.full_name(node.func)
        if full:
            self.check(full, node.lineno, "high", f"calls {full}", call=node)
        self.generic_visit(node)   # keep going: calls can contain other calls

    # --- helpers ------------------------------------------------------------

    def full_name(self, node):
        """Turn `r.generate_private_key` into its full dotted name using the nicknames."""
        parts = []
        while isinstance(node, ast.Attribute):    # peel off  .generate_private_key
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name) and node.id in self.aliases:
            parts.append(self.aliases[node.id])   # r  ->  cryptography...rsa
            return ".".join(reversed(parts))
        return None

    def check(self, full, line_number, confidence, detail, call=None):
        """If `full` belongs to a rule's python_names, record a hit."""
        for rule in self.rules:
            for name in rule.python_names:
                if full == name or full.startswith(name + "."):
                    if call is not None and rule.id == "RSA":
                        detail += key_size_note(call)
                    self.hits.append((line_number, rule, confidence, detail))
                    return


def key_size_note(call):
    """Read the key_size=... argument of an RSA call, if there is one."""
    for keyword in call.keywords:
        if keyword.arg == "key_size" and isinstance(keyword.value, ast.Constant):
            size = keyword.value.value
            note = f", key_size={size}"
            if isinstance(size, int) and size < 2048:
                note += " (below 2048 bits: weak even without a quantum computer)"
            return note
    return ""


def scan_python(text, rel_path, rules):
    """Return a list of Findings, or None if the file isn't valid Python."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None   # the caller falls back to the regex results

    visitor = CryptoVisitor(rules)
    visitor.visit(tree)

    lines = text.splitlines()
    findings = []
    seen = set()
    for line_number, rule, confidence, detail in visitor.hits:
        if (line_number, rule.id) in seen:
            continue   # one finding per rule per line
        seen.add((line_number, rule.id))
        findings.append(Finding(
            rule_id=rule.id,
            algorithm=rule.name,
            severity=rule.severity,
            file=rel_path,
            line=line_number,
            snippet=lines[line_number - 1].strip()[:120],
            confidence=confidence,
            replacement=rule.replacement,
            quantum_safe=rule.quantum_safe,
            detail=detail,
        ))
    return findings