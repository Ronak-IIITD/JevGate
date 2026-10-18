# Architecture

JevGate is an advisory security gateway with two integration surfaces:

- **HTTP API and dashboard:** FastAPI accepts request text, provenance-labeled evidence, and optional proposed tool calls.
- **MCP stdio server:** MCP hosts can call `inspect_untrusted_input` before acting on untrusted content or a proposed action.

Both surfaces route through the same inspection function. It tags request fields by origin, removes recognized credential-shaped values before model submission, requests Jev Router risk signals, compares reordered threat categories, applies deterministic policy, and records a redacted audit event.

```text
Agent host
  ├─ HTTP API ─┐
  └─ MCP tool ─┴─> Context/provenance ─> Local pattern checks ─> Jev Router
                                                │                    │
                                                └──────> Policy <─────┘
                                                           │
                                               allow / review / block
                                                           │
                                              Redacted local audit record
```

JevGate does not execute agent tools or establish user permissions. `ALLOW` means only that this gateway's configured checks passed. The integrating host must enforce the user's identity, permissions, tool schemas, and approval requirements independently.

For provider failures, malformed outputs, and audit failures, the API routes to review. MCP stdio is intended for a local host process; a remote deployment needs an authenticated transport and access controls before exposure.
