"""FastAPI service: RSA/EC key-strength risk assessment (`POST /assess`)
and the aggregate Certificate Transparency key survey (`GET /survey`).

There is no trained ML model here -- `/assess` is a rule-based lookup
against published NIST guidance (see risk.py), not a classifier, so
there's no model artifact to version or load. `/survey` reports only
aggregate statistics computed once at startup from the real, public CT
log data collected by scripts/download_data.py; no individual
certificate or key is ever returned by any endpoint.

Security notes (see SECURITY.md for the full policy):
- `/assess` never generates, stores, or receives an actual key -- only
  an algorithm name and a bit-length integer.
- Rate limiting caps how fast a single client can call either endpoint.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from cryptosentry import __version__
from cryptosentry.risk import assess
from cryptosentry.survey import RAW_PATH, load_survey, summary

logger = logging.getLogger("cryptosentry.api")
logging.basicConfig(level=logging.INFO)

REQUEST_COUNT = Counter("cryptosentry_requests_total", "Total requests", ["endpoint", "status"])
ASSESS_LATENCY = Histogram("cryptosentry_assess_latency_seconds", "Assess latency")

_RATE_LIMIT = os.environ.get("CRYPTOSENTRY_RATE_LIMIT", "120/minute")
limiter = Limiter(key_func=get_remote_address, default_limits=[_RATE_LIMIT])

app = FastAPI(title="CryptoSentry", version=__version__)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_survey_summary: dict | None = None


def get_survey_summary() -> dict | None:
    global _survey_summary
    if _survey_summary is None:
        path = Path(os.environ.get("CRYPTOSENTRY_SURVEY_PATH", str(RAW_PATH)))
        if not path.exists():
            return None
        _survey_summary = summary(load_survey(path))
        logger.info("loaded CT key survey: %d certificates", _survey_summary["n_certificates"])
    return _survey_summary


class AssessRequest(BaseModel):
    algorithm: str = Field(min_length=2, max_length=10)
    key_size_bits: int = Field(ge=1, le=16384)


class AssessResponse(BaseModel):
    algorithm: str
    key_size_bits: int
    classical_risk: str
    classical_rationale: str
    quantum_readiness: str
    pqc_recommendation: str
    migration_recommendation: str


@app.middleware("http")
async def _timing_and_metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    REQUEST_COUNT.labels(endpoint=request.url.path, status=response.status_code).inc()
    if request.url.path == "/assess":
        ASSESS_LATENCY.observe(elapsed)
    logger.info(
        "request path=%s status=%s latency_ms=%.2f",
        request.url.path,
        response.status_code,
        elapsed * 1000,
    )
    return response


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/model")
def model_info() -> dict:
    survey = get_survey_summary()
    return {
        "version": __version__,
        "has_ct_survey_data": survey is not None,
        "n_certificates_surveyed": survey["n_certificates"] if survey else 0,
    }


@app.get("/survey")
def survey_endpoint() -> dict:
    survey = get_survey_summary()
    if survey is None:
        return {"error": "no CT survey data loaded on this deployment"}
    return survey


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/assess", response_model=AssessResponse)
@limiter.limit(_RATE_LIMIT)
def assess_endpoint(request: Request, body: AssessRequest) -> AssessResponse:
    with ASSESS_LATENCY.time():
        try:
            result = assess(body.algorithm, body.key_size_bits)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    logger.info(
        "assess served algorithm=%s bits=%d risk=%s",
        result.algorithm,
        result.key_size_bits,
        result.classical_risk,
    )
    return AssessResponse(**result.as_dict())
