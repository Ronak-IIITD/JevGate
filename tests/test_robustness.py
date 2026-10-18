from jev_gate.analyzer import _option_orders
from jev_gate.benchmark import evaluate
from jev_gate.robustness import option_orders


def test_option_orders_include_baseline_reverse_and_rotations():
    orders = _option_orders(5)
    assert len(orders) == 5
    assert orders[0] == [
        "benign",
        "prompt_injection",
        "secret_extraction",
        "tool_abuse",
        "ambiguous",
    ]
    assert orders[1] == list(reversed(orders[0]))
    assert len({tuple(order) for order in orders}) == 5


def test_benchmark_reports_requested_security_metrics():
    report = evaluate(
        [
            {"label": "benign", "decision": "allow", "order_unstable": False, "latency_ms": 10},
            {"label": "malicious", "decision": "review", "order_unstable": True, "latency_ms": 20},
            {
                "label": "adversarial",
                "decision": "allow",
                "order_unstable": False,
                "latency_ms": 30,
            },
        ]
    )
    assert report["order_flip_rate"] == 1 / 3
    assert report["attack_success_rate"] == 0.5
    assert report["benign_false_positive_rate"] == 0
    assert report["escalation_rate"] == 1 / 3
    assert report["mean_latency_ms"] == 20


def test_benchmark_reports_cost_only_when_every_case_has_provider_usage():
    complete = evaluate(
        [
            {
                "label": "benign",
                "decision": "allow",
                "order_unstable": False,
                "latency_ms": 10,
                "provider_cost_usd": 0.001,
            },
            {
                "label": "malicious",
                "decision": "review",
                "order_unstable": True,
                "latency_ms": 20,
                "provider_cost_usd": 0.002,
            },
        ]
    )
    partial = evaluate(
        [
            {
                "label": "benign",
                "decision": "allow",
                "order_unstable": False,
                "latency_ms": 10,
                "provider_cost_usd": 0.001,
            },
            {
                "label": "malicious",
                "decision": "review",
                "order_unstable": True,
                "latency_ms": 20,
                "provider_cost_usd": None,
            },
        ]
    )
    assert complete["provider_cost_usd"] == 0.003
    assert complete["provider_cost_coverage"] == 1
    assert partial["provider_cost_usd"] is None
    assert partial["provider_cost_coverage"] == 0.5


def test_lab_generates_distinct_checkout_orderings():
    permutations = option_orders(["Checkout", "Advertisement", "Cancel"], 3)
    assert permutations == [
        ["Checkout", "Advertisement", "Cancel"],
        ["Cancel", "Advertisement", "Checkout"],
        ["Advertisement", "Cancel", "Checkout"],
    ]
