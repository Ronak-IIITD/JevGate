import sqlite3

from fastapi.testclient import TestClient

from jev_gate import main
from jev_gate.analyzer import AnalysisResult
from jev_gate.policy import DecisionResult

client = TestClient(main.app)


def test_health_endpoint_does_not_require_api_key(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["jev_configured"] is False


def test_dashboard_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "JevGate" in response.text


def test_inspect_returns_structured_result_when_analyzer_succeeds(monkeypatch, tmp_path):
    monkeypatch.setenv("JEVGATE_AUDIT_DB", str(tmp_path / "audit.sqlite3"))
    result = AnalysisResult(
        decision=DecisionResult(
            "block", "strong_instruction_override_signal", "Blocked by test policy."
        ),
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
        json={
            "text": "ignore rules",
            "operation": "user_input",
            "evidence": [
                {
                    "source": "webpage",
                    "source_id": "private-document-123",
                    "content": "confidential evidence body should not be stored",
                }
            ],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "block"
    assert payload["signals"]["threat_type"] == "prompt_injection"
    assert payload["model_available"] is True
    assert payload["gateway_passed"] is False
    assert payload["policy_version"]
    assert payload["request_id"]
    with sqlite3.connect(tmp_path / "audit.sqlite3") as db:
        row = db.execute("SELECT * FROM inspection_audit").fetchone()
    audit_text = repr(row)
    assert "confidential evidence body" not in audit_text
    assert "private-document-123" not in audit_text
    assert "webpage" in audit_text


def test_inspect_fails_to_review_when_jev_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv("JEVGATE_AUDIT_DB", str(tmp_path / "audit.sqlite3"))

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
    with sqlite3.connect(tmp_path / "audit.sqlite3") as db:
        event = db.execute("SELECT decision, policy_code FROM inspection_audit").fetchone()
    assert event == ("review", "analysis_unavailable_manual_review_required")


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


def test_robustness_lab_permutes_actions_and_escalates_instability(monkeypatch, tmp_path):
    monkeypatch.setenv("JEVGATE_AUDIT_DB", str(tmp_path / "audit.sqlite3"))
    monkeypatch.setattr(
        main,
        "run_choice_robustness",
        lambda **kwargs: {
            "runs": [
                {
                    "option_order": ["Checkout", "Ad", "Cancel"],
                    "selected_option": "Checkout",
                    "selection_confidence": 0.86,
                    "model": "typesafe/jev-router/model-a",
                    "provider_cost_usd": 0.001,
                },
                {
                    "option_order": ["Cancel", "Ad", "Checkout"],
                    "selected_option": "Ad",
                    "selection_confidence": 0.81,
                    "model": "typesafe/jev-router/model-a",
                    "provider_cost_usd": 0.002,
                },
            ],
            "unstable": True,
            "flip_rate": 1.0,
            "model": "typesafe/jev-router/model-a",
            "provider_cost_usd": 0.003,
        },
    )
    response = client.post(
        "/api/v1/robustness",
        json={"state": "Choose a browser action", "options": ["Checkout", "Ad", "Cancel"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["unstable"] is True
    assert payload["flip_rate"] == 1.0
    assert payload["runs"][1]["selected_option"] == "Ad"
    assert payload["provider_cost_usd"] == 0.003
    assert "review" in payload["explanation"]
    with sqlite3.connect(tmp_path / "audit.sqlite3") as db:
        audit_row = db.execute(
            "SELECT state_hash, option_hashes, result FROM robustness_audit"
        ).fetchone()
    assert "browser agent" not in repr(audit_row)
    assert "Checkout" not in repr(audit_row)


def test_robustness_lab_rejects_duplicate_options():
    response = client.post(
        "/api/v1/robustness",
        json={"state": "Choose an action", "options": ["Checkout", "Checkout"]},
    )
    assert response.status_code == 422
