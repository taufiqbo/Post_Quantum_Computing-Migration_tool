from pqc_scanner.rules import load_rules

VALID_SEVERITY = {"low", "medium", "high", "critical", "info"}

def test_all_rules_load():
    rules = load_rules()
    ids = [rule.id for rule in rules]
    assert len(rules) == 10
    assert "RSA" in ids
    assert "ML-KEM" in ids

def test_every_rule_has_valid_severity():
    for rule in load_rules():
        assert rule.severity in VALID_SEVERITY, f"Rule {rule.id} has invalid severity {rule.severity}"

def test_every_rule_has_patterns():
    for rule in load_rules():
        assert rule.patterns, f"Rule {rule.id} has no patterns"

def test_quantum_safe_rules_are_info():
    for rule in load_rules():
        if rule.quantum_safe:
            assert rule.severity == "info", f"Rule {rule.id} is safe but not info"

def test_key_exchange_Algorithms():
    rules = {rule.id: rule for rule in load_rules() }
    for rule_id in ("RSA", "ECC", "DH"):
        assert rules[rule_id].severity == "critical"
        assert rules[rule_id].hndl is True
