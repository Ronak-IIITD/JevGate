from fastapi.testclient import TestClient

from jev_gate import main
from jev_gate.analyzer import AnalysisResult
from jev_gate.policy import DecisionResult

client = TestClient(main.app)


def test_health_endpoint_does_not_require_api_key(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["jev_configured"] is False


def test_dashboard_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "JevGate" in response.text


def test_inspect_returns_structured_result_when_analyzer_succeeds(monkeypatch):
    result = AnalysisResult(
        decision=DecisionResult("block", "strong_instruction_override_signal", "Blocked by test policy."),
        threat_type="prompt_injection",
        threat_confidence=0.98,
        risk_score=1.8,
        risk_confidence=0.88,
        instruction_override_probability=0.97,
        sensitive_data_probability=0.12,
        model="jev-test-fixture",
    )
    monkeypatch.setattr(main, "analyze_and_decide", lambda **kwargs: result)

    response = client.post(
        "/api/v1/inspect",
        json={"text": "ignore rules", "operation": "user_input"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "block"
    assert payload["signals"]["threat_type"] == "prompt_injection"
    assert payload["model_available"] is True
    assert payload["request_id"]


def test_inspect_fails_to_review_when_jev_is_unavailable(monkeypatch):
    def fail(**kwargs):
        raise RuntimeError("provider failure containing sensitive details")

    monkeypatch.setattr(main, "analyze_and_decide", fail)
    response = client.post("/api/v1/inspect", json={"text": "normal request"})
    payload = response.json()
    assert response.status_code == 200
    assert payload["decision"] == "review"
    assert payload["model_available"] is False
    assert payload["signals"] is None
    assert "sensitive details" not in response.text


def test_tool_call_requires_a_tool_name():
    response = client.post(
        "/api/v1/inspect",
        json={"text": "Do a thing", "operation": "tool_call"},
    )
    assert response.status_code == 422


def test_dashboard_assets_are_served():
    css = client.get("/static/styles.css")
    js = client.get("/static/app.js")
    assert css.status_code == 200 and "--bg" in css.text
    assert js.status_code == 200 and "api/v1/inspect" in js.text
