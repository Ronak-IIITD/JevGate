"""Deterministic policy layer: model predictions are signals, never permissions."""

from dataclasses import dataclass

# Tools with irreversible, external, or privileged effects always require human review.
SIDE_EFFECT_TOOLS = {
    "send_email",
    "delete_file",
    "execute_shell",
    "publish_post",
    "transfer_money",
    "modify_permissions",
    "write_file",
    "create_user",
}

# Deliberately narrow. A tool must be explicitly listed here before the gateway
# can consider automatically allowing a tool call. Add tools only after reviewing
# their implementation and permissions.
READ_ONLY_TOOLS = {
    "search_public_docs",
    "search_public_web",
    "get_weather",
}

SUSPICIOUS_TYPES = {"prompt_injection", "secret_extraction", "tool_abuse"}


@dataclass(frozen=True)
class DecisionResult:
    decision: str
    policy_code: str
    explanation: str


def decide(
    *,
    operation: str,
    tool_name: str | None,
    threat_type: str,
    threat_confidence: float,
    risk_score: float,
    risk_confidence: float,
    instruction_override_probability: float,
    sensitive_data_probability: float,
) -> DecisionResult:
    """Apply conservative, auditable routing rules to Jev's predictions.

    Thresholds are prototype defaults, not validated security guarantees. Calibrate
    them against a representative labeled dataset before considering deployment.
    """
    normalized_tool = (tool_name or "").strip().lower()

    # Strong threat evidence takes precedence over tool type.
    if sensitive_data_probability >= 0.90 and risk_confidence >= 0.40:
        return DecisionResult(
            "block",
            "high_probability_sensitive_data_extraction",
            "The sensitive-data signal crossed the block threshold.",
        )

    if instruction_override_probability >= 0.85 and risk_confidence >= 0.40:
        return DecisionResult(
            "block",
            "strong_instruction_override_signal",
            "The instruction-override signal crossed the block threshold.",
        )

    if (
        threat_type in SUSPICIOUS_TYPES
        and threat_confidence >= 0.75
        and risk_score >= 1.35
        and risk_confidence >= 0.40
    ):
        return DecisionResult(
            "block",
            "confident_high_risk_classification",
            "Jev classified the content as suspicious with a sufficiently high risk score.",
        )

    if operation == "tool_call":
        if not normalized_tool:
            return DecisionResult(
                "review",
                "missing_tool_name",
                "The proposed tool has no name, so its permissions cannot be checked.",
            )
        if normalized_tool in SIDE_EFFECT_TOOLS:
            return DecisionResult(
                "review",
                "side_effect_tool_requires_approval",
                "This tool can change external state or perform a consequential action.",
            )
        if normalized_tool not in READ_ONLY_TOOLS:
            return DecisionResult(
                "review",
                "tool_not_allowlisted",
                "Unknown or unreviewed tools require human approval by default.",
            )

    low_risk = (
        threat_type == "benign"
        and threat_confidence >= 0.70
        and risk_score < 0.55
        and risk_confidence >= 0.50
        and instruction_override_probability < 0.20
        and sensitive_data_probability < 0.20
    )
    if low_risk:
        return DecisionResult(
            "allow",
            "low_risk_signals",
            "All configured low-risk conditions passed.",
        )

    return DecisionResult(
        "review",
        "uncertain_or_mixed_signals",
        "Signals are mixed or uncertain; human review is the conservative fallback.",
    )
