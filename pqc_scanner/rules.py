"""Load the YAML rules file and turn it into Python objects."""

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# The rules file lives next to this script, in pqc_scanner/rules/
DEFAULT_RULES = Path(__file__).parent / "rules" / "algorithms.yaml"


@dataclass
class Pattern:
    regex: re.Pattern     # a compiled regular expression
    confidence: str       # "high" = specific API call, "medium" = just the name


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    quantum_threat: str
    replacement: str
    hndl: bool = False
    quantum_safe: bool = False
    patterns: list = field(default_factory=list)
    python_names: list = field(default_factory=list)   # used by the AST scanner
    config_tokens: list = field(default_factory=list)  # used by the config scanner


def load_rules(path=DEFAULT_RULES):
    """Read the YAML file and return a list of Rule objects."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    rules = []
    for entry in data["algorithms"]:
        patterns = [
            Pattern(regex=re.compile(p["regex"]), confidence=p.get("confidence", "high"))
            for p in entry.get("patterns", [])
        ]
        rules.append(Rule(
            id=entry["id"],
            name=entry["name"],
            severity=entry["severity"],
            quantum_threat=entry["quantum_threat"],
            replacement=entry["replacement"],
            hndl=entry.get("hndl", False),
            quantum_safe=entry.get("quantum_safe", False),
            patterns=patterns,
            python_names=entry.get("python_names", []),
            config_tokens=[re.compile(t) for t in entry.get("config_tokens", [])],
        ))
    return rules


if __name__ == "__main__":
    # Quick self-test: python -m pqc_scanner.rules
    for rule in load_rules():
        print(f"{rule.id:8} {rule.severity:9} {len(rule.patterns)} pattern(s)  ->  {rule.replacement}")