from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


Operation = Literal["user_input", "tool_call"]
Decision = Literal["allow", "review", "block"]


class InspectRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000, description="Untrusted content to inspect")
    operation: Operation = "user_input"
    tool_name: str | None = Field(default=None, max_length=120)
    tool_arguments: str | None = Field(default=None, max_length=4_000)
    # Optional context is sent to TypeSafe for analysis; never put credentials here.
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


class InspectResponse(BaseModel):
    request_id: str
    decision: Decision
    policy_code: str
    explanation: str
    signals: Signals | None = None
    model: str
    model_available: bool
    latency_ms: float = Field(ge=0)
    # Input text is never echoed or stored by default.
