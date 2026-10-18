from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Operation = Literal["user_input", "tool_call"]
Decision = Literal["allow", "review", "block"]
EvidenceSource = Literal["email", "webpage", "document", "retrieval", "other"]


class UntrustedEvidence(BaseModel):
    source: EvidenceSource
    source_id: str | None = Field(default=None, max_length=160)
    content: str = Field(min_length=1, max_length=20_000)

    @field_validator("content")
    @classmethod
    def reject_blank_evidence(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence content must contain non-whitespace characters")
        return value


class InspectRequest(BaseModel):
    text: str = Field(
        min_length=1, max_length=20_000, description="User request or content to inspect"
    )
    evidence: list[UntrustedEvidence] = Field(default_factory=list, max_length=10)
    operation: Operation = "user_input"
    tool_name: str | None = Field(default=None, max_length=120)
    tool_arguments: str | None = Field(default=None, max_length=4_000)
    # Optional context is untrusted evidence; never put credentials here.
    context: str | None = Field(default=None, max_length=4_000)

    @field_validator("text")
    @classmethod
    def reject_whitespace_only(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must contain non-whitespace characters")
        return value

    @field_validator("tool_name")
    @classmethod
    def normalize_tool_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def require_tool_name_for_tool_call(self) -> InspectRequest:
        if self.operation == "tool_call" and not self.tool_name:
            raise ValueError("tool_name is required when operation='tool_call'")
        return self


class Signals(BaseModel):
    threat_type: str
    threat_confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=2.0)
    risk_confidence: float = Field(ge=0.0, le=1.0)
    instruction_override_probability: float = Field(ge=0.0, le=1.0)
    sensitive_data_probability: float = Field(ge=0.0, le=1.0)
    option_order_unstable: bool = False
    threat_type_variants: list[str] = Field(default_factory=list)
    deterministic_findings: list[dict[str, str]] = Field(default_factory=list)


class InspectResponse(BaseModel):
    request_id: str
    decision: Decision
    policy_code: str
    explanation: str
    signals: Signals | None = None
    model: str
    model_available: bool
    latency_ms: float = Field(ge=0)
    gateway_passed: bool = False
    policy_version: str
    robustness_runs: int = 0
    provider_cost_usd: float | None = Field(default=None, ge=0)
    robustness_call_costs_usd: list[float | None] = Field(default_factory=list)
    # ALLOW means gateway checks passed; the target application must still authorize actions.


class RobustnessRequest(BaseModel):
    state: str = Field(min_length=1, max_length=20_000, description="Untrusted state to assess")
    options: list[str] = Field(min_length=2, max_length=8)

    @field_validator("state")
    @classmethod
    def reject_blank_state(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("state must contain non-whitespace characters")
        return value

    @field_validator("options")
    @classmethod
    def validate_options(cls, value: list[str]) -> list[str]:
        normalized = [option.strip() for option in value]
        if any(not option or len(option) > 240 for option in normalized):
            raise ValueError("options must contain 1–240 non-whitespace characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("options must be unique")
        return normalized


class RobustnessRun(BaseModel):
    option_order: list[str]
    selected_option: str
    selection_confidence: float = Field(ge=0, le=1)
    model: str
    provider_cost_usd: float | None = Field(default=None, ge=0)


class RobustnessResponse(BaseModel):
    request_id: str
    available: bool
    unstable: bool | None = None
    flip_rate: float | None = Field(default=None, ge=0, le=1)
    runs: list[RobustnessRun] = Field(default_factory=list)
    explanation: str
    policy_version: str
    latency_ms: float = Field(ge=0)
    provider_cost_usd: float | None = Field(default=None, ge=0)
