import logging
import os
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .analyzer import MODEL, analyze_and_decide
from .schemas import InspectRequest, InspectResponse, Signals

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
    return {
        "status": "ok",
        "service": "jev-gate",
        "jev_configured": bool(os.getenv("TYPESAFE_API_KEY")),
        "model": MODEL,
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
        )
    except Exception as exc:  # Intentionally fail closed; don't return provider details to callers.
        # Log only the exception class, never the submitted text, context, credentials, or arguments.
        logger.warning("Inspection unavailable request_id=%s error_type=%s", request_id, type(exc).__name__)
        return InspectResponse(
            request_id=request_id,
            decision="review",
            policy_code="analysis_unavailable_manual_review_required",
            explanation="Jev analysis was unavailable; the request was routed to review by default.",
            signals=None,
            model=MODEL,
            model_available=False,
            latency_ms=round((perf_counter() - started) * 1000, 2),
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
        ),
        model=result.model,
        model_available=True,
        latency_ms=round((perf_counter() - started) * 1000, 2),
    )
