import pytest

from jev_gate.policy import decide


def signals(**overrides):
    values = {
        "threat_type": "benign",
        "threat_confidence": 0.92,
        "risk_score": 0.1,
        "risk_confidence": 0.9,
        "instruction_override_probability": 0.02,
        "sensitive_data_probability": 0.01,
    }
    values.update(overrides)
    return values


def test_clear_low_risk_user_input_is_allowed():
    result = decide(operation="user_input", tool_name=None, **signals())
    assert result.decision == "allow"
    assert result.policy_code == "low_risk_signals"


def test_side_effect_tool_always_requires_review():
    result = decide(operation="tool_call", tool_name="send_email", **signals())
    assert result.decision == "review"
    assert result.policy_code == "side_effect_tool_requires_approval"


def test_unknown_tool_requires_review_even_when_model_says_benign():
    result = decide(operation="tool_call", tool_name="my_unreviewed_tool", **signals())
    assert result.decision == "review"
    assert result.policy_code == "tool_not_allowlisted"


def test_allowlisted_read_only_tool_can_be_allowed_when_low_risk():
    result = decide(operation="tool_call", tool_name="search_public_docs", **signals())
    assert result.decision == "allow"


def test_high_sensitive_data_signal_is_blocked():
    result = decide(
        operation="user_input",
        tool_name=None,
        **signals(sensitive_data_probability=0.96, risk_confidence=0.75),
    )
    assert result.decision == "block"
    assert result.policy_code == "high_probability_sensitive_data_extraction"


def test_strong_instruction_override_is_blocked():
    result = decide(
        operation="user_input",
        tool_name=None,
        **signals(instruction_override_probability=0.92, risk_confidence=0.75),
    )
    assert result.decision == "block"


def test_low_confidence_mixed_signals_go_to_review():
    result = decide(
        operation="user_input",
        tool_name=None,
        **signals(
            threat_type="ambiguous",
            threat_confidence=0.42,
            risk_score=0.9,
            risk_confidence=0.3,
            instruction_override_probability=0.3,
            sensitive_data_probability=0.2,
        ),
    )
    assert result.decision == "review"
    assert result.policy_code == "uncertain_or_mixed_signals"


def test_unknown_tool_with_strong_attack_signal_is_blocked_before_review():
    result = decide(
        operation="tool_call",
        tool_name="unknown_tool",
        **signals(sensitive_data_probability=0.98, risk_confidence=0.9),
    )
    assert result.decision == "block"


@pytest.mark.parametrize("tool_name", ["", "   "])
def test_unknown_or_blank_tool_is_not_allowlisted(tool_name):
    result = decide(operation="tool_call", tool_name=tool_name, **signals())
    assert result.decision == "review"
