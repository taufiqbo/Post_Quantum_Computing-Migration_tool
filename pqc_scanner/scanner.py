"""Scanner #1: run the regex rules over every line of every source file."""

import os
import sys
from pathlib import Path

from .ast_scanner import scan_python
from .models import Finding
from .rules import load_rules

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
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        print(f"  could not read {path}: {err}", file=sys.stderr)
        return findings

    rel_path = path.relative_to(base).as_posix()
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


def scan_folder(folder, rules):
    """Walk through a folder and scan every source file inside it."""
    base = Path(folder).resolve()
    findings = []
    files_scanned = 0
    for dirpath, dirnames, filenames in os.walk(base):
        # Editing dirnames in place tells os.walk to skip those folders
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in SOURCE_EXTENSIONS:
                findings.extend(scan_file(path, rules, base))
                files_scanned += 1
    # Most severe first, then by file name and line number
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.file, f.line))
    return findings, files_scanned


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    rules = load_rules()
    findings, files_scanned = scan_folder(folder, rules)

    for f in findings:
        print(f"[{f.severity.upper():8}] {f.algorithm:28} {f.file}:{f.line}  ({f.confidence})")
        print(f"           {f.snippet}")
        if f.detail:
            print(f"           detail: {f.detail}")
        print(f"           fix: {f.replacement}")
        print()

    vulnerable = [f for f in findings if not f.quantum_safe]
    print(f"Scanned {files_scanned} files: {len(vulnerable)} quantum-vulnerable findings, "
          f"{len(findings) - len(vulnerable)} quantum-safe findings.")


if __name__ == "__main__":
    main()