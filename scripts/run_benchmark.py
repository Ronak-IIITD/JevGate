#!/usr/bin/env python3
"""Run the labeled JevGate benchmark against a local or remote gateway endpoint."""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

RULES = re.compile(
    r"ignore (all )?(previous|prior|system)|reveal|hidden prompt|credentials|api key|"
    r"upload all|exfiltrat|bypass (the )?(policy|safety)|override",
    re.IGNORECASE,
)


def rules_only(request):
    content = (
        request["text"] + " " + " ".join(item["content"] for item in request.get("evidence", []))
    )
    return "block" if RULES.search(content) else "allow"


def main():
    from jev_gate.benchmark import evaluate
    from jev_gate.policy import decide, validate_tool_arguments

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1/inspect")
    parser.add_argument("--dataset", default="data/adversarial_benchmark.jsonl")
    parser.add_argument("--output", default="benchmark-results.json")
    parser.add_argument(
        "--compare", help="previous JSON report; exit 2 if per-case decisions or flips changed"
    )
    parser.add_argument("--score-tolerance", type=float, default=0.05)
    args = parser.parse_args()

    cases = [
        json.loads(line) for line in Path(args.dataset).read_text().splitlines() if line.strip()
    ]
    measured = []
    for case in cases:
        body = json.dumps(case["request"]).encode()
        request = Request(args.url, data=body, headers={"Content-Type": "application/json"})
        started = time.perf_counter()
        with urlopen(request, timeout=180) as response:
            result = json.loads(response.read())
        latency_ms = (time.perf_counter() - started) * 1000
        signals = result.get("signals") or {}
        row = {
            "id": case["id"],
            "label": case["label"],
            "decision": result["decision"],
            "baseline_decision": decide(
                operation=case["request"].get("operation", "user_input"),
                tool_name=case["request"].get("tool_name"),
                threat_type=signals.get("threat_type", "ambiguous"),
                threat_confidence=signals.get("threat_confidence", 0),
                risk_score=signals.get("risk_score", 2),
                risk_confidence=signals.get("risk_confidence", 0),
                instruction_override_probability=signals.get("instruction_override_probability", 0),
                sensitive_data_probability=signals.get("sensitive_data_probability", 0),
                option_order_unstable=False,
                tool_arguments_valid=validate_tool_arguments(
                    case["request"].get("tool_name"), case["request"].get("tool_arguments")
                ),
            ).decision
            if signals
            else "review",
            "rules_only_decision": rules_only(case["request"]),
            "order_unstable": signals.get("option_order_unstable", False),
            "model": result.get("model"),
            "policy_version": result.get("policy_version"),
            "latency_ms": round(latency_ms, 2),
            "robustness_runs": result.get("robustness_runs", 0),
            "provider_cost_usd": result.get("provider_cost_usd"),
            "baseline_cost_usd": (result.get("robustness_call_costs_usd") or [None])[0],
            "signals": {
                name: signals.get(name)
                for name in (
                    "threat_type",
                    "threat_confidence",
                    "risk_score",
                    "risk_confidence",
                    "instruction_override_probability",
                    "sensitive_data_probability",
                )
            },
        }
        measured.append(row)

    report = {
        "dataset": args.dataset,
        "baseline_jev": evaluate(
            [
                {
                    **row,
                    "decision": row["baseline_decision"],
                    "provider_cost_usd": row["baseline_cost_usd"],
                }
                for row in measured
            ]
        ),
        "jev_with_order_checks": evaluate(measured),
        "rules_only": evaluate(
            [
                {
                    **row,
                    "decision": row["rules_only_decision"],
                    "order_unstable": False,
                    "provider_cost_usd": 0.0,
                }
                for row in measured
            ]
        ),
        "cases": measured,
        "provider_cost_note": "Provider costs are included when OpenRouter returns usage.cost; coverage is shown per metric.",
        "note": "Starter benchmark; review labels and expand with application-level adaptive attacks before drawing conclusions.",
    }
    drift = []
    if args.compare:
        previous = json.loads(Path(args.compare).read_text())
        old_cases = {row["id"]: row for row in previous.get("cases", [])}
        for current in measured:
            old = old_cases.get(current["id"])
            if not old:
                continue
            changed_signals = []
            old_signals = old.get("signals") or {}
            new_signals = current.get("signals") or {}
            for name, new_value in new_signals.items():
                old_value = old_signals.get(name)
                if isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)):
                    if abs(float(old_value) - float(new_value)) > args.score_tolerance:
                        changed_signals.append(name)
                elif old_value != new_value:
                    changed_signals.append(name)
            if (
                old.get("decision") != current["decision"]
                or old.get("order_unstable") != current["order_unstable"]
                or old.get("model") != current.get("model")
                or changed_signals
            ):
                drift.append(
                    {
                        "id": current["id"],
                        "old_decision": old.get("decision"),
                        "new_decision": current["decision"],
                        "old_order_unstable": old.get("order_unstable"),
                        "new_order_unstable": current["order_unstable"],
                        "model_changed": old.get("model") != current.get("model"),
                        "signals_changed": changed_signals,
                    }
                )
        report["behavior_drift"] = drift
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "baseline_jev",
                    "jev_with_order_checks",
                    "rules_only",
                    "provider_cost_note",
                )
            },
            indent=2,
        )
    )
    if drift:
        print(
            f"Behavior or model version changed in {len(drift)} benchmark cases; inspect {args.output}.",
            file=sys.stderr,
        )
        raise SystemExit(2)


if __name__ == "__main__":
    main()
