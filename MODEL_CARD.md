# Model Card: CryptoSentry

## Purpose

There is no trained ML model in this project. `POST /assess` is a
rule-based lookup against published NIST key-strength guidance
(`src/cryptosentry/risk.py`): given an algorithm (RSA or EC) and a key
size in bits, it returns a classical-risk tier, a PQC-readiness note,
and a migration recommendation, all traceable to a specific cited NIST
publication. Separately, this project surveys real, public keys from
real, public TLS certificates (via Certificate Transparency logs) to
report aggregate statistics (algorithm mix, key-size distribution,
RSA-vs-ECC share over time) -- not to train anything.

## Data

Certificate Transparency key survey: real public keys from real public
certificates, aggregated only (see [`data/README.md`](data/README.md)).
No private key belonging to anyone is ever accessed, and no
individual certificate's data is reported on its own.

## Rule thresholds (cited)

- **RSA**: <2048-bit = critical (NIST SP 800-131A Rev. 2, disallowed
  since 2013); 2048-bit = moderate (acceptable only through 2030);
  2049-3071-bit = moderate; >=3072-bit = low (recommended beyond 2030).
- **EC**: <224-bit = critical; 224-383-bit (e.g. P-256, ~128-bit
  security) = moderate; >=384-bit (e.g. P-384, ~192-bit security) = low.
- **Quantum readiness**: constant ("not quantum resistant") across
  every RSA/EC key size, since Shor's algorithm breaks both families in
  polynomial time regardless of key length -- a bigger classical key
  buys classical-attack margin, not quantum-attack margin.
- **PQC recommendation**: cites NIST FIPS 203 (ML-KEM), FIPS 204
  (ML-DSA), and FIPS 205 (SLH-DSA) -- the first NIST post-quantum
  cryptography standards, finalized August 2024.

## Limitations

- This is a coarse, key-size-only risk tier, not a full cryptographic
  audit -- it does not check padding schemes, protocol configuration,
  certificate chain validity, revocation status, or implementation-level
  vulnerabilities (side channels, weak randomness in a specific
  deployment, etc.).
- The CT key survey covers 20 domains chosen for renewal-history depth
  and sector/geographic diversity, not a statistically representative
  sample of the whole web -- see README's Limitations for the specific
  caveats this implies for the reported RSA-vs-ECC migration trend.
- PQC migration timelines cited are general guidance (NIST, NSA CNSA
  2.0), not a tailored risk assessment for any specific organization's
  threat model or data sensitivity lifetime.

## Not recommended for

Any real compliance, audit, or procurement decision without consulting
the actual cited NIST/NSA publications directly and a qualified
security professional. This is a portfolio demonstration of applying
published cryptographic guidance programmatically, not a certified
compliance tool.
