"""CyberMate Deterministic Expert System Inference Engine.
Evaluates facts against the declarative cybersecurity rule base,
computes confidence, ranks primary and related threats, synthesizes
actionable defensive responses, and calculates overall risk scores.
"""
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.rules.condition import Rule, RuleMatchResult


class ThreatDiagnosis(BaseModel):
    """Detailed diagnosis for a detected threat."""
    threat: str
    rule_id: str
    rule_name: str
    category: str
    severity: str
    confidence: float
    confidence_label: str
    mitre_technique: Optional[str] = None
    evidence: List[str]
    explanation: str
    recommendations: List[str]


class RiskBreakdown(BaseModel):
    category: str
    score: int
    max_score: int
    factors: List[str]


class SecurityRiskScore(BaseModel):
    """CyberMate Risk Score assessment."""
    score: int = Field(ge=0, le=100)
    level: str  # Low (0-25), Moderate (26-50), High (51-75), Critical (76-100)
    description: str
    contributing_factors: List[str]
    category_breakdowns: List[RiskBreakdown]
    urgent_actions: List[str]


class DiagnosisReport(BaseModel):
    """Complete diagnostic report returned by the CyberMate expert system."""
    has_threat: bool
    summary: str
    primary_threat: Optional[ThreatDiagnosis] = None
    related_threats: List[ThreatDiagnosis] = []
    all_matched_rules: List[RuleMatchResult] = []
    risk_score: SecurityRiskScore
    overall_recommendations: List[str] = []
    evaluated_facts: Dict[str, Any]
    evaluation_metadata: Dict[str, Any]


class ExpertSystemEngine:
    """Deterministic forward-chaining rule engine for cybersecurity threat detection."""

    SEVERITY_WEIGHTS = {
        "LOW": 1.0,
        "MEDIUM": 2.0,
        "HIGH": 3.5,
        "CRITICAL": 5.0
    }

    def __init__(self, rules: Optional[List[Rule]] = None):
        self._rules: List[Rule] = rules or []
        self._rules_by_id: Dict[str, Rule] = {r.id: r for r in self._rules}

    def register_rule(self, rule: Rule) -> None:
        """Register a new diagnostic rule."""
        self._rules.append(rule)
        self._rules_by_id[rule.id] = rule

    def register_rules(self, rules: List[Rule]) -> None:
        for r in rules:
            self.register_rule(r)

    @property
    def rules(self) -> List[Rule]:
        return self._rules

    def get_rule_count(self) -> int:
        return len(self._rules)

    def _determine_confidence_label(self, confidence: float) -> str:
        if confidence >= 0.85:
            return "Strong indication"
        elif confidence >= 0.70:
            return "Likely"
        elif confidence >= 0.50:
            return "Possible"
        elif confidence > 0.0:
            return "Low confidence"
        return "Uncertain"

    def _calculate_risk_score(self, facts: Dict[str, Any], matched_rules: List[RuleMatchResult]) -> SecurityRiskScore:
        """Calculates a deterministic 0-100 risk score with category breakdowns."""
        categories = [
            "Authentication", "Network", "System", "Account",
            "Endpoint", "Email", "Cloud", "Insider", "Application"
        ]

        category_scores: Dict[str, int] = {k: 0 for k in categories}
        category_factors: Dict[str, List[str]] = {k: [] for k in categories}
        all_factors: List[str] = []

        sev_points = {
            "CRITICAL": 35,
            "HIGH": 22,
            "MEDIUM": 12,
            "LOW": 6
        }

        has_critical = False
        has_high = False

        for match in matched_rules:
            cat = match.category if match.category in category_scores else "System"
            pts = sev_points.get(match.severity, 10)
            category_scores[cat] += pts

            if match.severity == "CRITICAL":
                has_critical = True
            elif match.severity == "HIGH":
                has_high = True

            factor_text = f"[{match.severity}] {match.rule_name} triggered ({len(match.evidence)} indicators)"
            category_factors[cat].append(factor_text)
            all_factors.append(factor_text)

        # Direct high-impact indicator contributions
        if facts.get("antivirus_disabled") is True:
            category_scores["Endpoint"] += 15
            all_factors.append("[Endpoint] Antivirus protection is disabled")

        if facts.get("mfa_disabled") is True:
            category_scores["Authentication"] += 15
            all_factors.append("[Authentication] Multi-Factor Authentication was deactivated")

        if facts.get("shadow_copy_deleted") is True:
            category_scores["System"] += 20
            all_factors.append("[System] Shadow copies deleted to obstruct recovery")

        if facts.get("unknown_process") is True or facts.get("unknown_executable") is True:
            category_scores["System"] += 8
            all_factors.append("[System] Unverified or suspicious executable running")

        if facts.get("large_data_transfer") is True or facts.get("unusual_outbound_traffic") is True:
            category_scores["Network"] += 10
            all_factors.append("[Network] Anomalous data transfer or external transmission")

        raw_sum = sum(category_scores.values())

        # Baseline floor enforcement for severe attacks
        if has_critical:
            # If at least one critical threat exists, score should start at least 65
            final_score = max(65, min(100, raw_sum))
            if len([m for m in matched_rules if m.severity == "CRITICAL"]) >= 2 or facts.get("mfa_disabled"):
                final_score = max(78, final_score)
        elif has_high:
            final_score = max(45, min(75, raw_sum))
        else:
            final_score = min(50, raw_sum)

        final_score = min(100, max(0, final_score))

        # Risk Level bracket
        if final_score <= 25:
            level = "Low"
            desc = "Normal baseline or minor low-risk observations. Maintain regular operational hygiene."
        elif final_score <= 50:
            level = "Moderate"
            desc = "Noticeable anomalous activities detected. Elevated monitoring and investigation advised."
        elif final_score <= 75:
            level = "High"
            desc = "Substantial evidence of active attack vector or system compromise. Containment recommended."
        else:
            level = "Critical"
            desc = "Immediate high-impact threat indicators present. Severe risk of compromise or loss."

        breakdowns = [
            RiskBreakdown(
                category=cat,
                score=min(100, score),
                max_score=100,
                factors=category_factors[cat]
            )
            for cat, score in category_scores.items()
            if score > 0 or cat in ["Authentication", "Network", "System"]
        ]

        # Prioritized urgent actions
        urgent = []
        if final_score >= 70:
            urgent.append("Isolate affected endpoints or accounts immediately from corporate network")
            urgent.append("Escalate incident to Tier 2/3 Security Operations / Incident Response team")
        if any("Authentication" in f or "MFA" in f or "Account" in f for f in all_factors):
            urgent.append("Force immediate credential reset and terminate active user sessions across all devices")
        if any("Endpoint" in f or "System" in f or "Antivirus" in f for f in all_factors):
            urgent.append("Initiate offline antimalware scanning and verify process integrity")
        if any("Network" in f or "Exfiltration" in f for f in all_factors):
            urgent.append("Block suspect destination IPs at perimeter firewalls and inspect egress traffic")

        if not urgent:
            urgent.append("Continue periodic audit log reviews and maintain standard defensive posture")

        return SecurityRiskScore(
            score=final_score,
            level=level,
            description=desc,
            contributing_factors=all_factors[:10],
            category_breakdowns=breakdowns,
            urgent_actions=urgent
        )

    def diagnose(self, facts: Dict[str, Any]) -> DiagnosisReport:
        """
        Runs deterministic inference over the supplied facts.
        Returns a complete DiagnosisReport.
        """
        start_time = time.perf_counter()

        matched_results: List[RuleMatchResult] = []
        for rule in self._rules:
            result = rule.evaluate(facts)
            if result.matched:
                matched_results.append(result)

        # Rank matched rules:
        def score_rule(r: RuleMatchResult) -> float:
            w = self.SEVERITY_WEIGHTS.get(r.severity, 1.0)
            return w * r.confidence

        matched_results.sort(key=score_rule, reverse=True)

        diagnoses: List[ThreatDiagnosis] = [
            ThreatDiagnosis(
                threat=m.threat,
                rule_id=m.rule_id,
                rule_name=m.rule_name,
                category=m.category,
                severity=m.severity,
                confidence=m.confidence,
                confidence_label=self._determine_confidence_label(m.confidence),
                mitre_technique=m.mitre_technique,
                evidence=m.evidence,
                explanation=m.explanation,
                recommendations=m.recommendations
            )
            for m in matched_results
        ]

        primary_threat = diagnoses[0] if diagnoses else None
        related_threats = diagnoses[1:6] if len(diagnoses) > 1 else []

        all_recs: List[str] = []
        seen_recs = set()
        for diag in diagnoses:
            for rec in diag.recommendations:
                if rec not in seen_recs:
                    seen_recs.add(rec)
                    all_recs.append(rec)

        risk_score = self._calculate_risk_score(facts, matched_results)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        has_threat = len(diagnoses) > 0

        if has_threat:
            summary = (
                f"Identified {len(diagnoses)} potential threat pattern(s). "
                f"Primary diagnosis: {primary_threat.threat} ({primary_threat.severity} severity, "
                f"{int(primary_threat.confidence * 100)}% confidence)."
            )
        else:
            summary = "No active threat signatures matched the provided facts. Maintain standard security posture."

        return DiagnosisReport(
            has_threat=has_threat,
            summary=summary,
            primary_threat=primary_threat,
            related_threats=related_threats,
            all_matched_rules=matched_results,
            risk_score=risk_score,
            overall_recommendations=all_recs[:10],
            evaluated_facts=facts,
            evaluation_metadata={
                "rules_evaluated": len(self._rules),
                "rules_fired": len(matched_results),
                "inference_time_ms": duration_ms,
                "engine_version": "1.0.0-deterministic"
            }
        )
