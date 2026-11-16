"""Automated unit and integration tests for CyberMate Expert System Engine.
Validates deterministic inference, multi-threat ranking, evidence tracing,
confidence scoring, and edge cases (no threat, simultaneous, low-confidence).
"""
import pytest
from app.rules.engine import ExpertSystemEngine
from app.rules.definitions import get_all_rules
from app.rules.condition import Rule, Condition


@pytest.fixture
def engine():
    eng = ExpertSystemEngine()
    eng.register_rules(get_all_rules())
    return eng


def test_brute_force_detection(engine):
    """Test standard brute force attack recognition."""
    facts = {
        "failed_login_count": 25,
        "successful_login_after_failures": False
    }
    report = engine.diagnose(facts)
    assert report.has_threat is True
    assert report.primary_threat is not None
    assert report.primary_threat.threat == "Brute Force Attack"
    assert report.primary_threat.severity == "HIGH"
    assert report.primary_threat.confidence >= 0.85
    assert len(report.primary_threat.recommendations) > 0
    assert any("rate limiting" in r.lower() for r in report.primary_threat.recommendations)


def test_account_takeover_detection(engine):
    """Test account takeover when successful login follows failures."""
    facts = {
        "failed_login_count": 20,
        "successful_login_after_failures": True,
        "login_from_unknown_ip": True,
        "password_changed_unexpectedly": True,
        "mfa_disabled": True
    }
    report = engine.diagnose(facts)
    assert report.has_threat is True
    assert report.primary_threat is not None
    assert report.primary_threat.threat in ["Account Takeover", "Defensive Neutralization / Account Hijacking"]
    assert report.primary_threat.severity == "CRITICAL"
    assert report.risk_score.score >= 60
    assert report.risk_score.level in ["High", "Critical"]
    assert len(report.overall_recommendations) > 0


def test_ransomware_detection(engine):
    """Test ransomware file encryption indicators."""
    facts = {
        "suspicious_file_activity": True,
        "high_cpu_usage": True,
        "shadow_copy_deleted": True
    }
    report = engine.diagnose(facts)
    assert report.has_threat is True
    assert any(t.threat == "Ransomware Indicators" for t in [report.primary_threat] + report.related_threats)
    assert report.risk_score.score >= 50


def test_suspicious_process_cryptominer(engine):
    """Test unsigned process consuming peak CPU."""
    facts = {
        "unknown_process": True,
        "high_cpu_usage": True
    }
    report = engine.diagnose(facts)
    assert report.has_threat is True
    assert report.primary_threat.threat == "Suspicious Process / Cryptominer"
    assert report.primary_threat.severity == "MEDIUM"


def test_phishing_detection(engine):
    """Test phishing email detection."""
    facts = {
        "phishing_indicators": True,
        "suspicious_attachment": True
    }
    report = engine.diagnose(facts)
    assert report.has_threat is True
    threat_names = [t.threat for t in [report.primary_threat] + report.related_threats]
    assert any("Phishing" in name or "Malware Delivery" in name for name in threat_names)


def test_no_threat_scenario(engine):
    """Test empty facts dictionary where no rules fire."""
    facts = {
        "failed_login_count": 1,
        "successful_login_after_failures": False,
        "unknown_process": False
    }
    report = engine.diagnose(facts)
    assert report.has_threat is False
    assert report.primary_threat is None
    assert report.risk_score.score <= 25
    assert report.risk_score.level == "Low"
    assert len(report.related_threats) == 0


def test_multiple_simultaneous_threats(engine):
    """Test ranking when both network exfiltration and brute force occur simultaneously."""
    facts = {
        "failed_login_count": 30,
        "large_data_transfer": True,
        "unknown_external_ip": True
    }
    report = engine.diagnose(facts)
    assert report.has_threat is True
    assert report.primary_threat is not None
    # Data exfiltration is CRITICAL whereas brute force is HIGH; CRITICAL should rank first
    assert report.primary_threat.threat == "Data Exfiltration Indicators"
    assert len(report.related_threats) >= 1
    assert any(t.threat == "Brute Force Attack" for t in report.related_threats)


def test_deterministic_consistency(engine):
    """Ensures identical input facts consistently yield exact identical results."""
    facts = {
        "failed_login_count": 12,
        "successful_login_after_failures": True,
        "login_from_unknown_ip": True
    }
    report1 = engine.diagnose(facts)
    report2 = engine.diagnose(facts)

    assert report1.primary_threat.threat == report2.primary_threat.threat
    assert report1.primary_threat.confidence == report2.primary_threat.confidence
    assert report1.risk_score.score == report2.risk_score.score
    assert report1.overall_recommendations == report2.overall_recommendations


def test_low_confidence_diagnosis(engine):
    """Test that partial match produces low confidence label rather than false certainty."""
    # Custom rule requiring 3 conditions with min_conditions_match=1
    test_rule = Rule(
        id="TEST-001",
        name="Test Partial Rule",
        category="Test",
        threat="Partial Test Threat",
        severity="LOW",
        base_confidence=0.50,
        conditions=[
            Condition(field="cond_a", operator="is_true"),
            Condition(field="cond_b", operator="is_true"),
            Condition(field="cond_c", operator="is_true"),
        ],
        min_conditions_match=1,
        explanation_template="Test explanation",
        recommendations=["Test rec"]
    )
    custom_engine = ExpertSystemEngine([test_rule])
    report = custom_engine.diagnose({"cond_a": True})
    assert report.has_threat is True
    # Matched 1 out of 3 conditions -> confidence is 0.50 * (1/3) = ~0.17 -> Low confidence
    assert report.primary_threat.confidence < 0.35
    assert report.primary_threat.confidence_label == "Low confidence"
