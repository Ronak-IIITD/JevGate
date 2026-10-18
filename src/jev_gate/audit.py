"""Redacted, local audit events. Raw request content and source identifiers are never stored."""

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_AUDIT_DB = ".jev_gate/audit.sqlite3"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _provenance(request: Any) -> list[dict[str, str | None]]:
    records: list[dict[str, str | None]] = [
        {"source": "user_input", "content_hash": digest(request.text)},
    ]
    if request.context:
        records.append({"source": "request_context", "content_hash": digest(request.context)})
    for item in request.evidence:
        records.append(
            {
                "source": item.source,
                "source_id_hash": digest(item.source_id) if item.source_id else None,
                "content_hash": digest(item.content),
            }
        )
    if request.tool_arguments:
        records.append(
            {"source": "proposed_tool_arguments", "content_hash": digest(request.tool_arguments)}
        )
    return records


def _lockfile_hash() -> str:
    lockfile = Path(__file__).resolve().parents[2] / "uv.lock"
    return hashlib.sha256(lockfile.read_bytes()).hexdigest() if lockfile.exists() else "unavailable"


def record_inspection(
    *,
    request_id: str,
    request: Any,
    result: Any,
    policy_version: str,
    latency_ms: float,
) -> None:
    """Persist decision metadata and hashes only; callers must fail closed on write errors."""
    path = Path(os.getenv("JEVGATE_AUDIT_DB", DEFAULT_AUDIT_DB)).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    signals = {
        "threat_type": result.threat_type,
        "threat_confidence": result.threat_confidence,
        "risk_score": result.risk_score,
        "risk_confidence": result.risk_confidence,
        "instruction_override_probability": result.instruction_override_probability,
        "sensitive_data_probability": result.sensitive_data_probability,
        "option_order_unstable": result.option_order_unstable,
        "threat_type_variants": result.threat_type_variants,
        "deterministic_findings": result.deterministic_findings,
        "robustness_signals": result.robustness_signals,
        "provider_cost_usd": result.provider_cost_usd,
        "dependency_lock_hash": _lockfile_hash(),
    }
    with sqlite3.connect(path, timeout=5) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS inspection_audit (
                request_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                input_hash TEXT NOT NULL,
                evidence_provenance TEXT NOT NULL,
                operation TEXT NOT NULL,
                tool_name TEXT,
                model TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                decision TEXT NOT NULL,
                policy_code TEXT NOT NULL,
                signals TEXT NOT NULL,
                latency_ms REAL NOT NULL
            )"""
        )
        connection.execute(
            """INSERT INTO inspection_audit (
                request_id, input_hash, evidence_provenance, operation, tool_name, model,
                policy_version, decision, policy_code, signals, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                request_id,
                digest(
                    json.dumps(
                        {
                            "text": request.text,
                            "context": request.context,
                            "tool_arguments": request.tool_arguments,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                ),
                json.dumps(_provenance(request), separators=(",", ":")),
                request.operation,
                request.tool_name,
                result.model,
                policy_version,
                result.decision.decision,
                result.decision.policy_code,
                json.dumps(signals, separators=(",", ":")),
                latency_ms,
            ),
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def record_unavailable(
    *,
    request_id: str,
    request: Any,
    model: str,
    policy_version: str,
    latency_ms: float,
) -> None:
    """Record provider or audit-path failures without retaining exception details."""
    path = Path(os.getenv("JEVGATE_AUDIT_DB", DEFAULT_AUDIT_DB)).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    with sqlite3.connect(path, timeout=5) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS inspection_audit (
                request_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                input_hash TEXT NOT NULL,
                evidence_provenance TEXT NOT NULL,
                operation TEXT NOT NULL,
                tool_name TEXT,
                model TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                decision TEXT NOT NULL,
                policy_code TEXT NOT NULL,
                signals TEXT NOT NULL,
                latency_ms REAL NOT NULL
            )"""
        )
        connection.execute(
            """INSERT INTO inspection_audit (
                request_id, input_hash, evidence_provenance, operation, tool_name, model,
                policy_version, decision, policy_code, signals, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                request_id,
                digest(
                    json.dumps(
                        {
                            "text": request.text,
                            "context": request.context,
                            "tool_arguments": request.tool_arguments,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                ),
                json.dumps(_provenance(request), separators=(",", ":")),
                request.operation,
                request.tool_name,
                model,
                policy_version,
                "review",
                "analysis_unavailable_manual_review_required",
                json.dumps(
                    {"available": False, "dependency_lock_hash": _lockfile_hash()},
                    separators=(",", ":"),
                ),
                latency_ms,
            ),
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def record_robustness_run(
    *,
    request_id: str,
    state: str,
    options: list[str],
    result: dict[str, Any],
    policy_version: str,
    latency_ms: float,
) -> None:
    """Store lab outcomes and hashes, replacing free-form option labels with their digests."""
    path = Path(os.getenv("JEVGATE_AUDIT_DB", DEFAULT_AUDIT_DB)).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    redacted_result = {
        "unstable": result.get("unstable"),
        "flip_rate": result.get("flip_rate"),
        "provider_cost_usd": result.get("provider_cost_usd"),
        "runs": [
            {
                "option_order_hashes": [digest(option) for option in run["option_order"]],
                "selected_option_hash": digest(run["selected_option"]),
                "selection_confidence": run["selection_confidence"],
                "model": run["model"],
                "provider_cost_usd": run.get("provider_cost_usd"),
            }
            for run in result.get("runs", [])
        ],
    }
    with sqlite3.connect(path, timeout=5) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS robustness_audit (
                request_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                state_hash TEXT NOT NULL,
                option_hashes TEXT NOT NULL,
                result TEXT NOT NULL,
                model TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                dependency_lock_hash TEXT NOT NULL
            )"""
        )
        connection.execute(
            """INSERT INTO robustness_audit (
                request_id, state_hash, option_hashes, result, model,
                policy_version, latency_ms, dependency_lock_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                request_id,
                digest(state),
                json.dumps([digest(option) for option in options], separators=(",", ":")),
                json.dumps(redacted_result, separators=(",", ":")),
                str(result.get("model", "unknown")),
                policy_version,
                latency_ms,
                _lockfile_hash(),
            ),
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
