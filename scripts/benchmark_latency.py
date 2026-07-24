"""Measure p50/p95/p99 latency and throughput of a running /assess endpoint.

Usage: python scripts/benchmark_latency.py --url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request

import numpy as np

SAMPLE_PAYLOAD = {"algorithm": "RSA", "key_size_bits": 2048}


def _post_assess(url: str) -> float:
    payload = json.dumps(SAMPLE_PAYLOAD).encode()
    req = urllib.request.Request(
        f"{url}/assess", data=payload, headers={"Content-Type": "application/json"}
    )
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed localhost URL)
        resp.read()
    return time.perf_counter() - start


def benchmark(url: str, n_requests: int) -> dict[str, float]:
    latencies = [_post_assess(url) for _ in range(n_requests)]
    latencies_ms = np.array(latencies) * 1000
    total_time = sum(latencies)
    return {
        "p50_ms": round(float(np.percentile(latencies_ms, 50)), 3),
        "p95_ms": round(float(np.percentile(latencies_ms, 95)), 3),
        "p99_ms": round(float(np.percentile(latencies_ms, 99)), 3),
        "throughput_req_per_s": round(n_requests / total_time, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--n-requests", type=int, default=50)
    args = parser.parse_args()

    results = benchmark(args.url, args.n_requests)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
