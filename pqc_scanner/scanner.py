"""Scanner #1: run the regex rules over every line of every source file."""

import os
import sys
from fnmatch import fnmatch
from pathlib import Path

from .ast_scanner import scan_python
from .cert_scanner import is_cert_file, scan_cert
from .config_scanner import is_config_file, scan_config
from .models import Finding

# Which file types we look inside
SOURCE_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".go", ".c", ".h", ".cpp", ".cs",
    ".rb", ".php", ".rs", ".kt", ".yaml", ".yml", ".json", ".xml",
}

# Folders we never look inside (too big, or not our code)
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}

COMMENT_STARTS = ("#", "//", "/*", "*")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def scan_file(path, rules, base):
    """Return a list of Findings for one file."""
    rel_path = path.relative_to(base).as_posix()

    # Certificates are often binary, so they get their own scanner BEFORE we read text
    if is_cert_file(path.name):
        return scan_cert(path, rel_path, rules)

    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        print(f"  could not read {path}: {err}", file=sys.stderr)
        return findings

    # Server config files get their own scanner
    if is_config_file(path.name):
        return scan_config(text, rel_path, rules)

    for line_number, line in enumerate(text.splitlines(), start=1):
        is_comment = line.strip().startswith(COMMENT_STARTS)
        for rule in rules:
            if is_comment and rule.quantum_safe:
                continue  # a comment can't prove we're quantum-safe, so skip those rules
            for pattern in rule.patterns:
                if pattern.regex.search(line):
                    findings.append(Finding(
                        rule_id=rule.id,
                        algorithm=rule.name,
                        severity=rule.severity,
                        file=rel_path,
                        line=line_number,
                        snippet=line.strip()[:120],
                        confidence="low" if is_comment else pattern.confidence,
                        replacement=rule.replacement,
                        quantum_safe=rule.quantum_safe,
                    ))
                    break  # one finding per rule per line is enough

    # Python files get a second, smarter look with the AST scanner
    if path.suffix == ".py":
        ast_findings = scan_python(text, rel_path, rules)
        if ast_findings is not None:
            # AST results win. Keep a regex finding only if the AST didn't
            # already report the same rule on the same line.
            taken = {(f.line, f.rule_id) for f in ast_findings}
            findings = ast_findings + [f for f in findings if (f.line, f.rule_id) not in taken]
    return findings


def is_excluded(name, exclude):
    """Does this file or folder name match one of the --exclude patterns?"""
    return any(fnmatch(name, pattern) for pattern in exclude)


def scan_folder(folder, rules, exclude=()):
    """Walk through a folder and scan every supported file inside it.

    exclude: file or folder name patterns to skip, e.g. ["tests", "*.yaml"]
    """
    base = Path(folder).resolve()
    findings = []
    files_scanned = 0
    for dirpath, dirnames, filenames in os.walk(base):
        # Editing dirnames in place tells os.walk to skip those folders
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not is_excluded(d, exclude)]
        for name in filenames:
            if is_excluded(name, exclude):
                continue
            path = Path(dirpath) / name
            if (path.suffix.lower() in SOURCE_EXTENSIONS
                    or is_config_file(name) or is_cert_file(name)):
                findings.extend(scan_file(path, rules, base))
                files_scanned += 1
    # Most severe first, then by file name and line number
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.file, f.line))
    return findings, files_scanned


if __name__ == "__main__":
    # The command-line part now lives in cli.py
    from .cli import main
    raise SystemExit(main())
