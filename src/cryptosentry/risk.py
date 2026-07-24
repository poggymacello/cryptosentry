"""Key-strength risk assessment against published NIST guidance, and a
PQC-readiness note against the finalized NIST post-quantum standards.

This is a literature-based classification, not a simulation: every
threshold cited here comes from a real, dated NIST publication (see
README's References), applied as a rule-based lookup against the
algorithm and key size a caller supplies. No cryptographic attack,
factoring, or key-breaking of any kind happens here.
"""

from __future__ import annotations

from dataclasses import dataclass

# NIST SP 800-131A Revision 2 (2019): RSA/DSA/DH key-length transitions.
# < 2048-bit: disallowed for new digital signature generation/verification
# since 2013 (legacy-use only, not recommended).
# 2048-bit: acceptable for use through 2030.
# >= 3072-bit: recommended for security beyond 2030.
RSA_DISALLOWED_MAX_BITS = 2047
RSA_ACCEPTABLE_THROUGH_2030_BITS = 2048
RSA_RECOMMENDED_BEYOND_2030_BITS = 3072

# NIST SP 800-186 / SP 800-57 Part 1 Rev. 5: elliptic curve key sizes
# and their approximate symmetric-equivalent security strength.
# P-224 (~112-bit), P-256 (~128-bit), P-384 (~192-bit), P-521 (~256-bit).
EC_DISALLOWED_MAX_BITS = 223
EC_ACCEPTABLE_THROUGH_2030_BITS = 224
# P-256 gives ~128-bit security strength (NIST SP 800-57 Part 1's
# strength-equivalence table), the same tier as RSA-3072; P-384 gives
# ~192-bit, the tier NIST associates with security well beyond 2030 --
# so the "recommended beyond 2030" floor here is P-384's 384 bits, not
# P-256's 256.
EC_RECOMMENDED_BEYOND_2030_BITS = 384


@dataclass(frozen=True)
class RiskAssessment:
    algorithm: str
    key_size_bits: int
    classical_risk: str  # "critical" | "high" | "moderate" | "low"
    classical_rationale: str
    quantum_readiness: str  # "not quantum resistant" -- Shor's algorithm breaks both RSA and EC
    pqc_recommendation: str
    migration_recommendation: str

    def as_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "key_size_bits": self.key_size_bits,
            "classical_risk": self.classical_risk,
            "classical_rationale": self.classical_rationale,
            "quantum_readiness": self.quantum_readiness,
            "pqc_recommendation": self.pqc_recommendation,
            "migration_recommendation": self.migration_recommendation,
        }


def _classical_risk_rsa(bits: int) -> tuple[str, str]:
    if bits <= RSA_DISALLOWED_MAX_BITS:
        return (
            "critical",
            f"{bits}-bit RSA is below NIST SP 800-131A Rev. 2's 2048-bit floor "
            "(disallowed for digital signature generation since 2013).",
        )
    if bits == RSA_ACCEPTABLE_THROUGH_2030_BITS:
        return (
            "moderate",
            "2048-bit RSA is acceptable per NIST SP 800-131A Rev. 2 only through 2030; "
            "not recommended for new deployments expected to remain in service beyond it.",
        )
    if RSA_ACCEPTABLE_THROUGH_2030_BITS < bits < RSA_RECOMMENDED_BEYOND_2030_BITS:
        return (
            "moderate",
            f"{bits}-bit RSA exceeds the 2048-bit floor but is below the "
            "3072-bit level NIST recommends for security beyond 2030.",
        )
    return (
        "low",
        f"{bits}-bit RSA meets or exceeds NIST SP 800-131A Rev. 2's 3072-bit "
        "recommendation for security beyond 2030 (classical risk only -- see "
        "quantum_readiness).",
    )


def _classical_risk_ec(bits: int) -> tuple[str, str]:
    if bits <= EC_DISALLOWED_MAX_BITS:
        return (
            "critical",
            f"{bits}-bit EC keys fall below NIST's 224-bit floor for approved curves.",
        )
    if bits < EC_RECOMMENDED_BEYOND_2030_BITS:
        return (
            "moderate",
            f"{bits}-bit EC (e.g. P-256, ~128-bit symmetric-equivalent strength) is "
            "approved and widely deployed, but below the ~192-256-bit-equivalent "
            "strength NIST associates with security well beyond 2030.",
        )
    return (
        "low",
        f"{bits}-bit EC meets or exceeds P-384-equivalent strength (classical risk "
        "only -- see quantum_readiness).",
    )


def assess(algorithm: str, key_size_bits: int) -> RiskAssessment:
    algo = algorithm.strip().upper()
    if algo == "RSA":
        classical_risk, rationale = _classical_risk_rsa(key_size_bits)
    elif algo in ("EC", "ECDSA", "ECDH"):
        classical_risk, rationale = _classical_risk_ec(key_size_bits)
        algo = "EC"
    else:
        raise ValueError(f"unsupported algorithm {algorithm!r}, expected RSA or EC")

    # Both RSA and elliptic-curve cryptography are broken in polynomial
    # time by Shor's algorithm on a sufficiently large fault-tolerant
    # quantum computer, regardless of key size -- increasing RSA/EC key
    # size buys classical-attack margin, not quantum-attack margin. This
    # is why "quantum_readiness" is constant across all RSA/EC key sizes:
    # the fix is a different algorithm family, not a bigger key.
    quantum_readiness = "not quantum resistant"
    pqc_recommendation = (
        "For confidentiality (key establishment): migrate to ML-KEM "
        "(NIST FIPS 203, finalized August 2024). For digital signatures: "
        "migrate to ML-DSA (NIST FIPS 204) or, where a stateless "
        "hash-based signature is preferred, SLH-DSA (NIST FIPS 205)."
    )

    migration_recommendation = _migration_recommendation(classical_risk)

    return RiskAssessment(
        algorithm=algo,
        key_size_bits=key_size_bits,
        classical_risk=classical_risk,
        classical_rationale=rationale,
        quantum_readiness=quantum_readiness,
        pqc_recommendation=pqc_recommendation,
        migration_recommendation=migration_recommendation,
    )


def _migration_recommendation(classical_risk: str) -> str:
    if classical_risk == "critical":
        return (
            "Rotate this key immediately; it does not meet current NIST minimum "
            "strength requirements regardless of quantum considerations."
        )
    if classical_risk == "moderate":
        return (
            "Plan a rotation to a NIST-recommended-beyond-2030 classical key size "
            "(RSA >=3072-bit or EC >=P-384) on your normal certificate/key renewal "
            "cycle, and begin tracking PQC migration guidance (NIST FIPS 203/204/205; "
            "NSA CNSA 2.0's 2025-2033 transition timeline for National Security "
            "Systems, a useful reference timeline even outside that specific scope) "
            "for anything expected to remain sensitive past the mid-2030s."
        )
    return (
        "No classical rotation urgency. Begin tracking PQC migration guidance "
        "(NIST FIPS 203/204/205; NSA CNSA 2.0's 2025-2033 transition timeline) for "
        "any use case where 'harvest now, decrypt later' matters -- i.e., where "
        "data encrypted today must remain confidential for longer than it will "
        "plausibly take a cryptographically relevant quantum computer to appear."
    )
