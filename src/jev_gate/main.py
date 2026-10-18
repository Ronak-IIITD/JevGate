import logging
import os
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .analyzer import MODEL, OPENROUTER_MODEL, analyze_and_decide
from .audit import record_inspection, record_robustness_run, record_unavailable
from .policy import POLICY_VERSION
from .robustness import run_choice_robustness
from .schemas import (
    InspectRequest,
    InspectResponse,
    RobustnessRequest,
    RobustnessResponse,
    RobustnessRun,
    Signals,
)

logger = logging.getLogger("jev_gate")
STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="JevGate",
    description=(
        "A prototype confidence-aware security gateway for AI application inputs and proposed tool calls. "
        "Jev provides signals; local policy code makes routing decisions."
    ),
    version="0.2.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, object]:
    openrouter_configured = bool(os.getenv("OPENROUTER_API_KEY"))
    typesafe_configured = bool(os.getenv("TYPESAFE_API_KEY"))
    return {
        "status": "ok",
        "service": "jev-gate",
        "jev_configured": openrouter_configured or typesafe_configured,
        "provider": "openrouter"
        if openrouter_configured
        else "typesafe"
        if typesafe_configured
        else None,
        "model": OPENROUTER_MODEL if openrouter_configured else MODEL,
    }


@app.post("/api/v1/inspect", response_model=InspectResponse)
def inspect(request: InspectRequest) -> InspectResponse:
    request_id = str(uuid4())
    started = perf_counter()
    try:
        result = analyze_and_decide(
            text=request.text,
            operation=request.operation,
            tool_name=request.tool_name,
            tool_arguments=request.tool_arguments,
            context=request.context,
            evidence=[item.model_dump() for item in request.evidence],
        )
        latency_ms = round((perf_counter() - started) * 1000, 2)
        record_inspection(
            request_id=request_id,
            request=request,
            result=result,
            policy_version=POLICY_VERSION,
            latency_ms=latency_ms,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed without exposing provider details.
        # Log only the exception class, never the submitted text, context, credentials, or arguments.
        logger.warning(
            "Inspection unavailable request_id=%s error_type=%s", request_id, type(exc).__name__
        )
        try:
            record_unavailable(
                request_id=request_id,
                request=request,
                model=OPENROUTER_MODEL if os.getenv("OPENROUTER_API_KEY") else MODEL,
                policy_version=POLICY_VERSION,
                latency_ms=round((perf_counter() - started) * 1000, 2),
            )
        except Exception as audit_exc:  # noqa: BLE001 - audit failure also keeps the result closed.
            logger.warning(
                "Fallback audit unavailable request_id=%s error_type=%s",
                request_id,
                type(audit_exc).__name__,
            )
        return InspectResponse(
            request_id=request_id,
            decision="review",
            policy_code="analysis_unavailable_manual_review_required",
            explanation="Jev analysis was unavailable; the request was routed to review by default.",
            signals=None,
            model=OPENROUTER_MODEL if os.getenv("OPENROUTER_API_KEY") else MODEL,
            model_available=False,
            latency_ms=round((perf_counter() - started) * 1000, 2),
            gateway_passed=False,
            policy_version=POLICY_VERSION,
            robustness_runs=0,
            provider_cost_usd=None,
            robustness_call_costs_usd=[],
        )

    return InspectResponse(
        request_id=request_id,
        decision=result.decision.decision,  # type: ignore[arg-type]
        policy_code=result.decision.policy_code,
        explanation=result.decision.explanation,
        signals=Signals(
            threat_type=result.threat_type,
            threat_confidence=result.threat_confidence,
            risk_score=result.risk_score,
            risk_confidence=result.risk_confidence,
            instruction_override_probability=result.instruction_override_probability,
            sensitive_data_probability=result.sensitive_data_probability,
            option_order_unstable=result.option_order_unstable,
            threat_type_variants=result.threat_type_variants or [],
            deterministic_findings=result.deterministic_findings or [],
        ),
        model=result.model,
        model_available=True,
        latency_ms=round((perf_counter() - started) * 1000, 2),
        gateway_passed=result.decision.decision == "allow",
        policy_version=POLICY_VERSION,
        robustness_runs=len(result.threat_type_variants or []),
        provider_cost_usd=result.provider_cost_usd,
        robustness_call_costs_usd=[
            float(run["provider_cost_usd"])
            if isinstance(run.get("provider_cost_usd"), (int, float))
            else None
            for run in (result.robustness_signals or [])
        ],
    )


@app.post("/api/v1/robustness", response_model=RobustnessResponse)
def robustness_lab(request: RobustnessRequest) -> RobustnessResponse:
    request_id = str(uuid4())
    started = perf_counter()
    try:
        result = run_choice_robustness(state=request.state, options=request.options)
        latency_ms = round((perf_counter() - started) * 1000, 2)
        record_robustness_run(
            request_id=request_id,
            state=request.state,
            options=request.options,
            result=result,
            policy_version=POLICY_VERSION,
            latency_ms=latency_ms,
        )
        unstable = bool(result["unstable"])
        return RobustnessResponse(
            request_id=request_id,
            available=True,
            unstable=unstable,
            flip_rate=float(result["flip_rate"]),
            runs=[RobustnessRun(**run) for run in result["runs"]],
            explanation=(
                "The selected option changed across orderings; route this case to review. "
                "A stable result does not authorize the action."
                if unstable
                else "No option-order change appeared in these runs. This does not authorize the action."
            ),
            policy_version=POLICY_VERSION,
            latency_ms=latency_ms,
            provider_cost_usd=(
                float(result["provider_cost_usd"])
                if result.get("provider_cost_usd") is not None
                else None
            ),
        )
    except Exception as exc:  # noqa: BLE001 - lab failures must never imply a stable decision.
        logger.warning(
            "Robustness lab unavailable request_id=%s error_type=%s", request_id, type(exc).__name__
        )
        return RobustnessResponse(
            request_id=request_id,
            available=False,
            unstable=None,
            flip_rate=None,
            runs=[],
            explanation="Robustness assessment was unavailable; require review before proceeding.",
            policy_version=POLICY_VERSION,
            latency_ms=round((perf_counter() - started) * 1000, 2),
            provider_cost_usd=None,
        )
