# Threat model

## Protected interests

- Prevent untrusted content from changing application policy or granting itself permissions.
- Reduce the chance that an agent follows prompt injection, extracts secrets, or misuses a tool.
- Avoid forwarding recognized credential-shaped values to the model provider.
- Preserve enough redacted metadata to review decisions without retaining raw inspected content.

## In scope

- Direct and indirect prompt injection in user text, emails, web pages, retrieved documents, request context, and proposed tool arguments.
- Attempts to extract hidden prompts, credentials, or private data.
- Tool calls with unsafe, unknown, malformed, or consequential behavior.
- Option-order sensitivity and model/provider behavior changes.
- Provider outage, malformed model responses, and audit-write failures.

## Out of scope and assumptions

- Complete detection of novel, obfuscated, multilingual, multimodal, or context-dependent attacks.
- Authentication and authorization of the user in the integrating application.
- Enforcing that an MCP host invokes JevGate or obeys its response.
- Security of target tools, host instructions, provider infrastructure, or the deployment environment.
- Preventing disclosure of credentials that do not match the built-in formats.

## Security controls

- Request text, context, and evidence are treated as untrusted; trusted policy comes from server configuration.
- Deterministic patterns supplement model risk assessment. They are not a proof of safety.
- Model output cannot authorize tool execution. Consequential tool calls require review, and all tool-call requests currently require downstream authorization.
- Uncertainty and unavailable checks route to review.
- Audit records store hashes, provenance labels, model signals, decisions, and versions rather than raw request content.
- Recognized token-shaped credentials are redacted before provider submission. The format list is incomplete, so do not send sensitive content unless your deployment permits provider processing.

## Evaluation

Use the benchmark and robustness lab to measure attack success, benign false positives, escalation, option-order flips, latency, and cost. Include adaptive attacks against the complete application workflow. Results describe the tested corpus and configuration; they do not establish universal resistance.
