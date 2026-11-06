###The finding class: one place where we found a piece of cryptography###

from dataclasses import dataclass

@dataclass
class Finding:
    rule_id: str
    algorithm: str
    severity: str
    file: str
    line: int
    snippet: str
    confidence: str
    replacement: str
    quantum_safe: bool = False
    detail: str = ""