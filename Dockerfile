FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

RUN pip install --no-cache-dir uv==0.9.2
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000
CMD ["uvicorn", "jev_gate.main:app", "--host", "0.0.0.0", "--port", "8000"]
