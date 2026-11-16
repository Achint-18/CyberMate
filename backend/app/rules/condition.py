"""Condition and Rule abstractions for the CyberMate Expert System engine.
Deterministic rule evaluation with transparent evidence generation.
"""
from typing import Any, Dict, List, Optional, Tuple, Literal
from pydantic import BaseModel, Field


OperatorType = Literal[
    "eq", "neq", "gt", "gte", "lt", "lte", "contains", "in", "is_true", "is_false", "exists"
]


class Condition(BaseModel):
    """A condition that must be evaluated against the observed facts dictionary."""
    field: str
    operator: OperatorType = "eq"
    value: Any = None
    description: Optional[str] = None

    def evaluate(self, facts: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Evaluates this condition against facts.
        Returns:
            Tuple[bool, str]: (matched, reason_description)
        """
        fact_val = facts.get(self.field)

        if self.operator == "exists":
            matched = fact_val is not None
            text = f"Fact '{self.field}' is present" if matched else f"Fact '{self.field}' is missing"
            return matched, text

        if self.operator == "is_true":
            matched = bool(fact_val) is True
            desc = self.description or f"Observed {self.field.replace('_', ' ')}"
            return matched, desc if matched else f"{self.field} was not observed"

        if self.operator == "is_false":
            matched = bool(fact_val) is False
            desc = self.description or f"{self.field.replace('_', ' ')} is false"
            return matched, desc

        if fact_val is None:
            return False, f"Indicator '{self.field}' not provided"

        matched = False
        try:
            if self.operator == "eq":
                matched = (fact_val == self.value)
            elif self.operator == "neq":
                matched = (fact_val != self.value)
            elif self.operator == "gt":
                matched = (float(fact_val) > float(self.value))
            elif self.operator == "gte":
                matched = (float(fact_val) >= float(self.value))
            elif self.operator == "lt":
                matched = (float(fact_val) < float(self.value))
            elif self.operator == "lte":
                matched = (float(fact_val) <= float(self.value))
            elif self.operator == "contains":
                matched = str(self.value).lower() in str(fact_val).lower()
            elif self.operator == "in":
                if isinstance(self.value, (list, tuple, set)):
                    matched = fact_val in self.value
                else:
                    matched = str(fact_val).lower() in str(self.value).lower()
        except (ValueError, TypeError):
            matched = False

        desc = self.description or f"{self.field.replace('_', ' ')} {self.operator} {self.value} (actual: {fact_val})"
        return matched, desc


class RuleMatchResult(BaseModel):
    """Result of evaluating a single rule against facts."""
    rule_id: str
    rule_name: str
    category: str
    threat: str
    severity: str
    matched: bool
    confidence: float
    evidence: List[str]
    missing_evidence: List[str]
    mitre_technique: Optional[str] = None
    explanation: str
    recommendations: List[str]


class Rule(BaseModel):
    """A cybersecurity diagnostic rule."""
    id: str
    name: str
    category: str
    threat: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    base_confidence: float = Field(default=0.85, ge=0.1, le=1.0)
    mitre_technique: Optional[str] = None
    conditions: List[Condition]
    # If None, ALL conditions must match (standard conjunctive rule)
    # If int, at least this many conditions must match
    min_conditions_match: Optional[int] = None
    explanation_template: str
    recommendations: List[str]

    def evaluate(self, facts: Dict[str, Any]) -> RuleMatchResult:
        evidence: List[str] = []
        missing_evidence: List[str] = []
        matched_count = 0

        for cond in self.conditions:
            is_match, reason = cond.evaluate(facts)
            if is_match:
                matched_count += 1
                evidence.append(reason)
            else:
                missing_evidence.append(reason)

        total_conds = len(self.conditions)
        threshold = self.min_conditions_match if self.min_conditions_match is not None else total_conds

        rule_fired = matched_count >= threshold and total_conds > 0

        # Confidence calculation:
        # Based on base_confidence scaled by the ratio of matched conditions
        match_ratio = (matched_count / total_conds) if total_conds > 0 else 0
        computed_confidence = round(self.base_confidence * match_ratio, 2)
        if not rule_fired:
            computed_confidence = 0.0

        # Build dynamic explanation
        if rule_fired:
            bullets = "\n".join(f"• {e}" for e in evidence)
            explanation = f"{self.explanation_template}\n\nEvidence observed:\n{bullets}"
        else:
            explanation = f"Rule did not fire. Matched {matched_count}/{threshold} required indicators."

        return RuleMatchResult(
            rule_id=self.id,
            rule_name=self.name,
            category=self.category,
            threat=self.threat,
            severity=self.severity,
            matched=rule_fired,
            confidence=computed_confidence,
            evidence=evidence,
            missing_evidence=missing_evidence,
            mitre_technique=self.mitre_technique,
            explanation=explanation,
            recommendations=self.recommendations
        )
