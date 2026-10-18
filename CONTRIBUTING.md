# Contributing

Thanks for helping improve JevGate. Contributions should keep the security boundary explicit: JevGate provides risk signals and routing decisions; the host application remains responsible for authentication, authorization, approvals, and tool execution.

## Development setup

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen --extra dev
cp .env.example .env
# Set OPENROUTER_API_KEY in .env or in your local process environment.
uv run pytest
uv run ruff check .
```

Never commit `.env`, provider credentials, raw user evidence, local audit databases, or benchmark reports containing sensitive data. Tests should use mocked provider calls and synthetic input; they must not require a live API key.

## Pull requests

- Keep changes focused and explain the security or user-facing effect.
- Add or update tests for behavior changes.
- Update the README or `docs/` when interfaces, setup, policy, or deployment behavior changes.
- Run the test and lint commands above before opening a pull request.
- Do not claim a detector prevents all prompt injection. Include its known limitations and evaluation evidence.

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) for vulnerability reports. Do not open a public issue containing exploit details or credentials.
