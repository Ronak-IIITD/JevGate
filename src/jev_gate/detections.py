"""Small deterministic pre-screen for common, explicit attack phrases.

These rules catch known patterns; they are not a complete prompt-injection detector.
"""

import re
import unicodedata
from collections.abc import Iterable

_CREDENTIAL_VALUE_PATTERN = re.compile(
    r"(?:sk-or-v1-[a-f0-9]{32,}|sk-[A-Za-z0-9_-]{24,}|"
    r"gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
    r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.I,
)


_RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "credential_like_value",
        "secret_exposure",
        "high",
        re.compile(
            r"\b(?:sk-or-v1-[a-f0-9]{32,}|sk-[A-Za-z0-9_-]{24,}|"
            r"gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})\b"
            r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.I,
        ),
    ),
    (
        "instruction_override_direct",
        "prompt_injection",
        "high",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass|replace)\b.{0,70}\b"
            r"(all\s+)?(previous|prior|above|system|developer|earlier)\s+"
            r"(instructions?|rules?|messages?|prompts?)\b",
            re.I,
        ),
    ),
    (
        "secret_extraction_direct",
        "secret_extraction",
        "high",
        re.compile(
            r"\b(reveal|disclose|print|show|output|dump|repeat|exfiltrate|extract|leak)\b"
            r".{0,100}\b(hidden\s+)?(system\s+prompt|developer\s+prompt|"
            r"credentials?|passwords?|api\s+keys?|access\s+tokens?|secrets?|"
            r"environment\s+variables?)\b",
            re.I,
        ),
    ),
    (
        "guardrail_bypass_direct",
        "prompt_injection",
        "high",
        re.compile(
            r"\b(bypass|disable|turn\s+off|ignore)\b.{0,70}\b"
            r"(safety|security|guardrails?|content\s+filter|policy\s+checks?)\b",
            re.I,
        ),
    ),
    (
        "unauthorized_external_transfer",
        "tool_abuse",
        "high",
        re.compile(
            r"\b(send|upload|forward|export|transfer)\b.{0,120}\b"
            r"(secret|credential|password|token|private\s+data|customer\s+data|"
            r"database|files?)\b.{0,100}\b(external|public|unknown|attacker|"
            r"without\s+(approval|permission|consent))\b",
            re.I,
        ),
    ),
    (
        "concealed_instruction_marker",
        "ambiguous",
        "review",
        re.compile(
            r"\b(from\s+now\s+on|new\s+system\s+prompt|developer\s+override|"
            r"secretly\s+follow|do\s+not\s+tell\s+the\s+user)\b",
            re.I,
        ),
    ),
)


def _normalize(text: str) -> str:
    # NFKC folds common compatibility characters; remove invisible format controls.
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(char for char in normalized if unicodedata.category(char) != "Cf")


def redact_credential_values(text: str) -> str:
    """Redact common credential formats before sending inspected state to a model."""
    return _CREDENTIAL_VALUE_PATTERN.sub("[REDACTED_CREDENTIAL]", text)


def detect_attack_patterns(
    *,
    text: str,
    context: str | None = None,
    evidence: Iterable[dict[str, str | None]] = (),
    tool_name: str | None = None,
    tool_arguments: str | None = None,
) -> list[dict[str, str]]:
    """Return rule IDs and source labels without retaining matched content."""
    sources: list[tuple[str, str]] = [("user_input", text)]
    if context:
        sources.append(("request_context", context))
    sources.extend(
        (str(item.get("source") or "other"), str(item.get("content") or ""))
        for item in evidence
    )
    if tool_name:
        sources.append(("proposed_tool_name", tool_name))
    if tool_arguments:
        sources.append(("proposed_tool_arguments", tool_arguments))

    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for source, content in sources:
        normalized = _normalize(content)
        for rule_id, category, severity, pattern in _RULES:
            key = (rule_id, source)
            if key not in seen and pattern.search(normalized):
                findings.append(
                    {
                        "rule_id": rule_id,
                        "category": category,
                        "severity": severity,
                        "source": source,
                    }
                )
                seen.add(key)
    return findings
