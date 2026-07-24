"""Aggregate analysis of the real Certificate Transparency key survey
(see data/README.md and scripts/download_data.py).

Every number here is a count or a percentage over public keys from
public certificates -- no individual certificate's data is reported on
its own, only aggregates across the whole collected sample. See
README's Leakage Controls-equivalent section (this project doesn't have
a model to leak, but the same "investigate the data before trusting a
number" discipline applies to a survey too) for what the raw counts
looked like before aggregation.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

RAW_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "raw" / "ct_key_survey.csv"


def load_survey(path: Path | None = None) -> list[dict]:
    target = path or RAW_PATH
    with open(target, newline="") as f:
        return list(csv.DictReader(f))


def algorithm_distribution(rows: list[dict]) -> dict[str, float]:
    counts = Counter(row["key_algorithm"] for row in rows)
    total = sum(counts.values())
    return {algo: round(count / total, 4) for algo, count in counts.most_common()}


def rsa_key_size_distribution(rows: list[dict]) -> dict[int, int]:
    sizes = Counter(
        int(row["key_size_bits"]) for row in rows if row["key_algorithm"] == "RSA"
    )
    return dict(sorted(sizes.items()))


def rsa_public_exponent_distribution(rows: list[dict]) -> dict[str, int]:
    exponents = Counter(
        row["rsa_public_exponent"] for row in rows if row["key_algorithm"] == "RSA"
    )
    return dict(exponents.most_common())


def ec_curve_distribution(rows: list[dict]) -> dict[str, int]:
    curves = Counter(row["ec_curve"] for row in rows if row["key_algorithm"] == "EC")
    return dict(curves.most_common())


def algorithm_share_by_month(rows: list[dict]) -> dict[str, dict[str, float]]:
    """RSA vs. EC share of certificates logged in each (year, month) --
    the finest real-data temporal resolution this single-year CT log
    snapshot supports. See README's Method section for why this is a
    within-year snapshot, not a multi-year migration measurement (that
    part of the README is sourced from cited literature instead)."""
    by_month: dict[str, Counter] = {}
    for row in rows:
        key = f"{row['ct_timestamp_year']}-{int(row['ct_timestamp_month']):02d}"
        by_month.setdefault(key, Counter())[row["key_algorithm"]] += 1

    result = {}
    for month_key, counts in sorted(by_month.items()):
        total = sum(counts.values())
        result[month_key] = {algo: round(count / total, 4) for algo, count in counts.items()}
    return result


def summary(rows: list[dict]) -> dict:
    return {
        "n_certificates": len(rows),
        "algorithm_distribution": algorithm_distribution(rows),
        "rsa_key_size_distribution": rsa_key_size_distribution(rows),
        "rsa_public_exponent_distribution": rsa_public_exponent_distribution(rows),
        "ec_curve_distribution": ec_curve_distribution(rows),
        "algorithm_share_by_month": algorithm_share_by_month(rows),
    }
