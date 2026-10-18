"""Deterministic policy layer: model predictions are signals, never permissions."""

import json
from dataclasses import dataclass

POLICY_VERSION = "2026-10-18.1"

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

TOOL_ARGUMENT_FIELDS = {
    "search_public_docs": {"query": str},
    "search_public_web": {"query": str},
    "get_weather": {"location": str},
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
    option_order_unstable: bool = False,
    tool_arguments_valid: bool = False,
    deterministic_findings: list[dict[str, str]] | None = None,
) -> DecisionResult:
    """Apply conservative, auditable routing rules to Jev's predictions.

    Thresholds are prototype defaults, not validated security guarantees. Calibrate
    them against a representative labeled dataset before considering deployment.
    """
    normalized_tool = (tool_name or "").strip().lower()

    findings = deterministic_findings or []
    high_findings = [finding for finding in findings if finding.get("severity") == "high"]
    if high_findings:
        categories = ", ".join(sorted({finding["category"] for finding in high_findings}))
        sources = ", ".join(sorted({finding["source"] for finding in high_findings}))
        return DecisionResult(
            "block",
            "deterministic_attack_pattern",
            f"Local security rules matched a high-risk {categories} pattern in {sources}.",
        )
    if findings:
        categories = ", ".join(sorted({finding["category"] for finding in findings}))
        return DecisionResult(
            "review",
            "deterministic_suspicious_pattern",
            f"Local security rules found suspicious {categories} content; review before proceeding.",
        )

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

    if option_order_unstable:
        return DecisionResult(
            "review",
            "option_order_instability",
            "The threat classification changed when category options were reordered.",
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
        if not tool_arguments_valid:
            return DecisionResult(
                "review",
                "tool_arguments_invalid",
                "Tool arguments did not pass the configured deterministic schema check.",
            )
        return DecisionResult(
            "review",
            "authorization_required_downstream",
            "Gateway signals passed, but this service has no authenticated user permission check. "
            "The calling application must authorize the user and tool arguments before execution.",
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


def validate_tool_arguments(tool_name: str | None, raw_arguments: str | None) -> bool:
    """Validate known read-only tool argument objects against local allowlisted schemas."""
    fields = TOOL_ARGUMENT_FIELDS.get((tool_name or "").strip().lower())
    if fields is None or not raw_arguments:
        return False
    try:
        arguments = json.loads(raw_arguments)
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(arguments, dict) or set(arguments) != set(fields):
        return False
    return all(
        isinstance(arguments[name], expected_type) and bool(arguments[name].strip())
        for name, expected_type in fields.items()
    )
