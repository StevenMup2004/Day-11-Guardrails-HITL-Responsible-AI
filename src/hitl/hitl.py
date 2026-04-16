"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 12: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        clamped_confidence = max(0.0, min(1.0, confidence))

        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=clamped_confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        if clamped_confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=clamped_confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )

        if clamped_confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=clamped_confidence,
                reason="Medium confidence - needs review",
                priority="normal",
                requires_human=True,
            )

        return RoutingDecision(
            action="escalate",
            confidence=clamped_confidence,
            reason="Low confidence - escalating",
            priority="high",
            requires_human=True,
        )


# ============================================================
# TODO 13: Design 3 HITL decision points
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large Transaction Authorization",
        "trigger": "Transfer or withdrawal above policy threshold (for example >= 50,000,000 VND) or unusual destination account.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "User identity signals, transaction amount, destination account risk score, account history, and model rationale.",
        "example": "A user who usually transfers below 5,000,000 VND suddenly requests 120,000,000 VND to a new beneficiary at 2 AM.",
    },
    {
        "id": 2,
        "name": "Potential Data Leakage Review",
        "trigger": "Any response flagged by content filter or judge as possible secret, PII, or policy-violating disclosure.",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Original user prompt, raw model output, redacted output, matched guardrail patterns, and safety judge verdict.",
        "example": "The assistant response includes text resembling an API key and an internal hostname; reviewer decides redact vs block.",
    },
    {
        "id": 3,
        "name": "Conflicting Recommendation Resolution",
        "trigger": "Confidence router and safety judge disagree, or two policy engines produce contradictory decisions.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "All model candidates, confidence scores, policy outputs, conversation history, and customer intent summary.",
        "example": "Router predicts high confidence auto-send, but judge marks response UNSAFE due to ambiguous compliance wording.",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
