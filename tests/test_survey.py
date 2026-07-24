import csv
from pathlib import Path

from cryptosentry.survey import (
    algorithm_distribution,
    algorithm_share_by_month,
    ec_curve_distribution,
    load_survey,
    rsa_key_size_distribution,
    rsa_public_exponent_distribution,
    summary,
)

FIELDNAMES = [
    "log_index", "ct_timestamp_year", "ct_timestamp_month", "issuer",
    "key_algorithm", "key_size_bits", "rsa_public_exponent", "ec_curve",
]


def _write_csv(path: Path, rows: list[dict]) -> Path:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _row(year, month, algo, bits, exponent="", curve=""):
    return {
        "log_index": "1",
        "ct_timestamp_year": str(year),
        "ct_timestamp_month": str(month),
        "issuer": "C=US, O=Test CA",
        "key_algorithm": algo,
        "key_size_bits": str(bits) if bits else "",
        "rsa_public_exponent": str(exponent) if exponent else "",
        "ec_curve": curve,
    }


def test_load_survey_round_trips(tmp_path):
    path = _write_csv(tmp_path / "survey.csv", [_row(2026, 3, "RSA", 2048, 65537)])
    rows = load_survey(path)
    assert len(rows) == 1
    assert rows[0]["key_algorithm"] == "RSA"


def test_algorithm_distribution_sums_to_one():
    rows = [_row(2026, 1, "RSA", 2048, 65537)] * 3 + [_row(2026, 1, "EC", 256, curve="secp256r1")]
    dist = algorithm_distribution(rows)
    assert abs(sum(dist.values()) - 1.0) < 1e-9
    assert dist["RSA"] == 0.75
    assert dist["EC"] == 0.25


def test_rsa_key_size_distribution_ignores_ec_rows():
    rows = [
        _row(2026, 1, "RSA", 2048, 65537),
        _row(2026, 1, "RSA", 4096, 65537),
        _row(2026, 1, "EC", 256, curve="secp256r1"),
    ]
    dist = rsa_key_size_distribution(rows)
    assert dist == {2048: 1, 4096: 1}


def test_rsa_public_exponent_distribution_dominant_65537():
    rows = [_row(2026, 1, "RSA", 2048, 65537)] * 9 + [_row(2026, 1, "RSA", 2048, 3)]
    dist = rsa_public_exponent_distribution(rows)
    assert dist["65537"] == 9
    assert dist["3"] == 1


def test_ec_curve_distribution_ignores_rsa_rows():
    rows = [_row(2026, 1, "EC", 256, curve="secp256r1"), _row(2026, 1, "RSA", 2048, 65537)]
    dist = ec_curve_distribution(rows)
    assert dist == {"secp256r1": 1}


def test_algorithm_share_by_month_shows_variation():
    rows = (
        [_row(2026, 1, "RSA", 2048, 65537)] * 9
        + [_row(2026, 1, "EC", 256, curve="secp256r1")]
        + [_row(2026, 6, "RSA", 2048, 65537)]
        + [_row(2026, 6, "EC", 256, curve="secp256r1")] * 9
    )
    share = algorithm_share_by_month(rows)
    assert share["2026-01"]["RSA"] > share["2026-06"]["RSA"]
    assert share["2026-06"]["EC"] > share["2026-01"]["EC"]


def test_summary_has_all_expected_keys():
    rows = [_row(2026, 1, "RSA", 2048, 65537), _row(2026, 2, "EC", 256, curve="secp256r1")]
    report = summary(rows)
    assert report["n_certificates"] == 2
    assert set(report.keys()) == {
        "n_certificates", "algorithm_distribution",
        "rsa_key_size_distribution", "rsa_public_exponent_distribution",
        "ec_curve_distribution", "algorithm_share_by_month",
    }
