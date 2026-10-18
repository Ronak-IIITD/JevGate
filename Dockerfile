FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    JEVGATE_AUDIT_DB=/data/audit.sqlite3
WORKDIR /app

RUN pip install --no-cache-dir uv==0.9.2
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN addgroup --system app && adduser --system --ingroup app app \
    && mkdir -p /data \
    && uv sync --frozen --no-dev \
    && chown -R app:app /app /data
ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000
VOLUME ["/data"]
USER app
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1
CMD ["uvicorn", "jev_gate.main:app", "--host", "0.0.0.0", "--port", "8000"]
