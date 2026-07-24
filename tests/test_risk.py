import pytest

from cryptosentry.risk import assess


def test_rsa_1024_is_critical():
    result = assess("RSA", 1024)
    assert result.classical_risk == "critical"


def test_rsa_2048_is_moderate():
    result = assess("RSA", 2048)
    assert result.classical_risk == "moderate"


def test_rsa_4096_is_low():
    result = assess("RSA", 4096)
    assert result.classical_risk == "low"


def test_ec_256_is_moderate():
    result = assess("EC", 256)
    assert result.classical_risk == "moderate"


def test_ec_384_is_low():
    result = assess("EC", 384)
    assert result.classical_risk == "low"


def test_ec_192_is_critical():
    result = assess("EC", 192)
    assert result.classical_risk == "critical"


def test_quantum_readiness_is_constant_regardless_of_key_size():
    weak = assess("RSA", 1024)
    strong = assess("RSA", 4096)
    assert weak.quantum_readiness == strong.quantum_readiness == "not quantum resistant"


def test_pqc_recommendation_cites_nist_standards():
    result = assess("RSA", 2048)
    assert "FIPS 203" in result.pqc_recommendation
    assert "FIPS 204" in result.pqc_recommendation


def test_unsupported_algorithm_raises():
    with pytest.raises(ValueError):
        assess("DSA", 2048)


def test_ecdsa_alias_normalizes_to_ec():
    result = assess("ECDSA", 256)
    assert result.algorithm == "EC"


def test_as_dict_round_trips_all_fields():
    result = assess("RSA", 2048)
    d = result.as_dict()
    assert d["algorithm"] == "RSA"
    assert d["key_size_bits"] == 2048
    assert set(d.keys()) == {
        "algorithm", "key_size_bits", "classical_risk", "classical_rationale",
        "quantum_readiness", "pqc_recommendation", "migration_recommendation",
    }
