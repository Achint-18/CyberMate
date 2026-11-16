"""API endpoint tests for CyberMate."""
import pytest
from app.database.db import SessionLocal
from app.api.analyze import list_indicators, analyze_incident, calculate_risk_score
from app.api.chat import chat_diagnose
from app.api.threats import list_threats, get_threat, list_active_rules
from app.api.scenarios import list_scenarios, get_scenario, run_scenario
from app.api.password import generate_password
from app.api.dashboard import fetch_metrics
from app.schemas.incident import AnalyzeRequest, ChatDiagnosisRequest
from app.services.password_service import PasswordGenerateRequest


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


def test_list_indicators_endpoint():
    indicators = list_indicators()
    assert len(indicators) >= 20
    assert any(i.id == "failed_login_count" for i in indicators)


def test_analyze_incident_endpoint(db):
    req = AnalyzeRequest(
        title="Direct Endpoint Test",
        facts={"failed_login_count": 12, "login_from_unknown_ip": True},
        save_to_history=True
    )
    report = analyze_incident(req, db=db)
    assert report.has_threat is True
    assert report.primary_threat.threat == "Brute Force Attack"
    assert report.risk_score.score > 0


def test_chat_diagnosis_endpoint(db):
    req = ChatDiagnosisRequest(
        query="Someone tried logging into my account 20 times and then successfully logged in from an unknown IP.",
        save_to_history=True
    )
    res = chat_diagnose(req, db=db)
    assert len(res.extracted_observations) > 0
    assert res.extracted_facts.get("failed_login_count") == 20
    assert res.diagnosis_report.has_threat is True


def test_calculate_risk_score_endpoint():
    facts = {"failed_login_count": 25, "antivirus_disabled": True}
    risk = calculate_risk_score(facts)
    assert risk.score >= 40
    assert risk.level in ["Moderate", "High", "Critical"]


def test_threat_endpoints():
    threats = list_threats(query=None, category=None)
    assert len(threats) >= 8

    # Search filter
    filtered = list_threats(query="phishing", category=None)
    assert len(filtered) >= 1

    # Rules listing
    rules = list_active_rules()
    assert len(rules) >= 40


def test_scenarios_endpoints(db):
    scenarios = list_scenarios()
    assert len(scenarios) >= 5

    scen = get_scenario("SCENARIO-ATO")
    assert scen.id == "SCENARIO-ATO"

    report = run_scenario("SCENARIO-ATO", db=db)
    assert report.has_threat is True
    assert report.primary_threat.threat in ["Account Takeover", "Defensive Neutralization / Account Hijacking"]


def test_password_generator_endpoint():
    req = PasswordGenerateRequest(
        length=24,
        use_uppercase=True,
        use_lowercase=True,
        use_numbers=True,
        use_symbols=True,
        exclude_ambiguous=True
    )
    res = generate_password(req)
    assert len(res.password) == 24
    assert res.entropy_bits >= 100
    assert res.strength == "Very Strong"


def test_dashboard_metrics_endpoint(db):
    metrics = fetch_metrics(db=db)
    assert metrics.rules_active_count >= 40
    assert metrics.threat_library_count >= 8
    assert metrics.incidents_analyzed >= 0
