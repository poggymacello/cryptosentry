# syntax=docker/dockerfile:1

FROM python:3.11-slim AS builder

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && pip install --no-cache-dir .

FROM python:3.11-slim AS runtime

RUN groupadd --gid 10001 cryptosentry \
    && useradd --uid 10001 --gid cryptosentry --create-home --shell /usr/sbin/nologin cryptosentry

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    CRYPTOSENTRY_SURVEY_PATH=/app/data/ct_key_survey.csv

WORKDIR /app
COPY --chown=cryptosentry:cryptosentry data/sample/ct_key_survey_sample.csv ./data/ct_key_survey.csv

USER cryptosentry

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "cryptosentry.api:app", "--host", "0.0.0.0", "--port", "8000"]
