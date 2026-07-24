"""Collect a real, aggregate-only key survey directly from a live public
Certificate Transparency log (RFC 6962), via Cloudflare's Nimbus2026 log.

Every certificate this script reads is public by design: Certificate
Transparency is an append-only, publicly auditable log that every
publicly-trusted CA is required to submit certificates to -- querying a
log directly (`get-sth` / `get-entries`, both unauthenticated GET
requests over HTTPS) is the intended, documented way to read it. This
script parses only each entry's PUBLIC key (algorithm, size, curve,
public exponent) and CT log timestamp, and writes only that aggregate
metadata to a CSV -- never a private key (none exist to access; CT logs
only ever contain public certificates), never anything about a specific
end-user, and no raw certificate DER is retained past the parsing step.

An earlier version of this script used crt.sh (a community search
service over CT logs); crt.sh was found to be entirely unreachable when
this was written (verified with a direct request, not assumed), so this
version queries a live log directly via RFC 6962 instead of a search
mirror. Nimbus2026 only contains certificates submitted during 2026, so
this collects a real, current snapshot of the live key population --
not a multi-year time series; the README's RSA-to-ECC migration
discussion is sourced from cited literature for that reason, not from
this snapshot (see README's Method section for the distinction).
"""

from __future__ import annotations

import base64
import csv
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
OUT_PATH = RAW_DIR / "ct_key_survey.csv"

LOG_BASE_URL = "https://ct.cloudflare.com/logs/nimbus2026"
N_SAMPLES = 400
REQUEST_TIMEOUT = 12
MAX_RETRIES = 3


def _get_with_retry(url: str) -> bytes | None:
    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
                return resp.read()
        except (urllib.error.URLError, TimeoutError):
            time.sleep(1.5 * (attempt + 1))
    return None


def _get_tree_size() -> int | None:
    body = _get_with_retry(f"{LOG_BASE_URL}/ct/v1/get-sth")
    if body is None:
        return None
    return json.loads(body)["tree_size"]


def _get_entry_cert_der(index: int) -> tuple[bytes, int] | None:
    """Returns (certificate DER bytes, CT log timestamp in ms) for one
    log entry, or None if the entry couldn't be fetched or isn't
    parseable with the simple approach here (see module docstring:
    x509_entry types embed the full cert directly; precert_entry types
    embed the pre-certificate, which carries the same public key)."""
    body = _get_with_retry(f"{LOG_BASE_URL}/ct/v1/get-entries?start={index}&end={index}")
    if body is None:
        return None
    try:
        entries = json.loads(body)["entries"]
    except (json.JSONDecodeError, KeyError):
        return None
    if not entries:
        return None

    leaf = base64.b64decode(entries[0]["leaf_input"])
    timestamp_ms = int.from_bytes(leaf[2:10], "big")
    entry_type = int.from_bytes(leaf[10:12], "big")

    if entry_type == 0:  # x509_entry: cert DER is embedded directly
        length = int.from_bytes(leaf[12:15], "big")
        cert_der = leaf[15 : 15 + length]
    elif entry_type == 1:  # precert_entry: pre-certificate is in extra_data
        extra = base64.b64decode(entries[0]["extra_data"])
        length = int.from_bytes(extra[0:3], "big")
        cert_der = extra[3 : 3 + length]
    else:
        return None
    return cert_der, timestamp_ms


def _parse_cert(cert_der: bytes, timestamp_ms: int, index: int) -> dict | None:
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError:
        return None

    public_key = cert.public_key()
    logged_at = time.gmtime(timestamp_ms / 1000)
    row = {
        "log_index": index,
        "ct_timestamp_year": logged_at.tm_year,
        "ct_timestamp_month": logged_at.tm_mon,
        "issuer": cert.issuer.rfc4514_string(),
    }
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        row.update(
            {
                "key_algorithm": "RSA",
                "key_size_bits": public_key.key_size,
                "rsa_public_exponent": numbers.e,
                "ec_curve": "",
            }
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        row.update(
            {
                "key_algorithm": "EC",
                "key_size_bits": public_key.key_size,
                "rsa_public_exponent": "",
                "ec_curve": public_key.curve.name,
            }
        )
    else:
        row.update(
            {
                "key_algorithm": type(public_key).__name__,
                "key_size_bits": "",
                "rsa_public_exponent": "",
                "ec_curve": "",
            }
        )
    return row


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    if OUT_PATH.exists():
        print(f"{OUT_PATH.name}: already present, skipping (delete it to re-collect)")
        return

    print(f"fetching current tree size from {LOG_BASE_URL}...")
    tree_size = _get_tree_size()
    if tree_size is None:
        print("FATAL: could not reach the CT log's get-sth endpoint.", file=sys.stderr)
        sys.exit(1)
    print(f"tree_size={tree_size}")

    # sample evenly across the whole log rather than only the most recent
    # entries, to at least spread across the log's full (2026) window
    step = tree_size // N_SAMPLES
    indices = [i * step for i in range(N_SAMPLES)]

    rows = []
    for n, index in enumerate(indices):
        result = _get_entry_cert_der(index)
        if result is not None:
            cert_der, timestamp_ms = result
            row = _parse_cert(cert_der, timestamp_ms, index)
            if row is not None:
                rows.append(row)
        if (n + 1) % 50 == 0:
            print(f"  {n + 1}/{len(indices)} entries processed, {len(rows)} parsed so far")

    if not rows:
        print("FATAL: collected zero certificates from the log.", file=sys.stderr)
        sys.exit(1)

    with open(OUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "log_index", "ct_timestamp_year", "ct_timestamp_month", "issuer",
                "key_algorithm", "key_size_bits", "rsa_public_exponent", "ec_curve",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{OUT_PATH.name}: {len(rows)} certificates written to {OUT_PATH}")


if __name__ == "__main__":
    main()
