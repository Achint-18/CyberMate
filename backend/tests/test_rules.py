"""Tests for rule catalog integrity, condition evaluators, and operators."""
import pytest
from app.rules.definitions import get_all_rules
from app.rules.condition import Condition


def test_rule_count_requirement():
    """Verify that CyberMate satisfies requirement 33 (at least 30-50 well-designed rules)."""
    rules = get_all_rules()
    assert len(rules) >= 40, f"Expected at least 40 rules, found {len(rules)}"
    assert len(rules) <= 60


def test_rule_structure_integrity():
    """Verify that every rule has valid ID, severity, category, recommendations, and conditions."""
    rules = get_all_rules()
    seen_ids = set()

    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    for r in rules:
        assert r.id not in seen_ids, f"Duplicate rule ID found: {r.id}"
        seen_ids.add(r.id)

        assert r.name, f"Rule {r.id} missing name"
        assert r.threat, f"Rule {r.id} missing threat classification"
        assert r.severity in valid_severities, f"Rule {r.id} invalid severity: {r.severity}"
        assert len(r.conditions) > 0, f"Rule {r.id} has no conditions"
        assert len(r.recommendations) > 0, f"Rule {r.id} has no defensive recommendations"
        assert r.explanation_template, f"Rule {r.id} missing explanation template"


def test_condition_operators():
    """Test individual condition operator mechanics."""
    c_eq = Condition(field="status", operator="eq", value="active")
    assert c_eq.evaluate({"status": "active"})[0] is True
    assert c_eq.evaluate({"status": "inactive"})[0] is False

    c_gte = Condition(field="count", operator="gte", value=5)
    assert c_gte.evaluate({"count": 5})[0] is True
    assert c_gte.evaluate({"count": 10})[0] is True
    assert c_gte.evaluate({"count": 4})[0] is False

    c_true = Condition(field="flag", operator="is_true")
    assert c_true.evaluate({"flag": True})[0] is True
    assert c_true.evaluate({"flag": False})[0] is False
    assert c_true.evaluate({})[0] is False
