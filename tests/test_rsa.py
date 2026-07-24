import random
import secrets

import pytest

from cryptosentry.rsa import decrypt, encrypt, generate_keypair


def test_keygen_produces_real_distinct_primes_and_valid_modulus():
    keypair = generate_keypair(bits=64, rng=random.Random(1))
    assert keypair.p != keypair.q
    assert keypair.n == keypair.p * keypair.q
    assert keypair.n.bit_length() in (63, 64)  # product of two 32-bit primes


def test_encrypt_decrypt_round_trip():
    keypair = generate_keypair(bits=128, rng=random.Random(2))
    message = b"hello rsa"
    ciphertext = encrypt(message, keypair.n, keypair.e)
    recovered = decrypt(ciphertext, keypair.n, keypair.d)
    assert recovered == message


def test_round_trip_across_multiple_messages_and_seeds():
    for seed in (1, 2, 3, 4, 5):
        keypair = generate_keypair(bits=128, rng=random.Random(seed))
        for message in (b"a", b"test message", b"rsa bytes here"):
            ciphertext = encrypt(message, keypair.n, keypair.e)
            assert decrypt(ciphertext, keypair.n, keypair.d) == message


def test_leading_zero_bytes_are_not_preserved():
    # documented limitation of raw/unpadded RSA: a message and the same
    # message with leading zero bytes stripped encode to the same integer,
    # so decrypt cannot tell them apart. Real RSA uses fixed-length padded
    # encoding (e.g. OAEP) specifically to avoid this.
    keypair = generate_keypair(bits=128, rng=random.Random(8))
    padded = b"\x00\x01rsa"
    stripped = b"\x01rsa"
    ciphertext = encrypt(padded, keypair.n, keypair.e)
    assert decrypt(ciphertext, keypair.n, keypair.d) == stripped


def test_ciphertext_differs_from_plaintext_and_is_deterministic():
    keypair = generate_keypair(bits=64, rng=random.Random(6))
    message = b"secret"
    c1 = encrypt(message, keypair.n, keypair.e)
    c2 = encrypt(message, keypair.n, keypair.e)
    assert c1 == c2  # textbook RSA is deterministic, no padding/randomization
    assert c1 != int.from_bytes(message, "big")


def test_message_too_long_for_key_raises():
    keypair = generate_keypair(bits=32, rng=random.Random(7))
    too_long = b"this message is definitely too long for a 32-bit key"
    with pytest.raises(ValueError):
        encrypt(too_long, keypair.n, keypair.e)


def test_default_keygen_uses_a_secure_rng_not_a_seeded_one():
    # regression test for the v1 -> v2 CSPRNG fix: calling generate_keypair()
    # with no rng argument must not silently fall back to a seedable PRNG.
    # Two default-rng keypairs at the same bit length must not be
    # reproducible from a fixed seed the way random.Random(seed) would be.
    keypair_a = generate_keypair(bits=64)
    keypair_b = generate_keypair(bits=64)
    assert keypair_a.n != keypair_b.n

    seeded_a = generate_keypair(bits=64, rng=random.Random(123))
    seeded_b = generate_keypair(bits=64, rng=random.Random(123))
    assert seeded_a.n == seeded_b.n  # the explicit escape hatch is still reproducible


def test_generate_keypair_default_rng_is_a_systemrandom_instance(monkeypatch):
    calls = []
    original_init = secrets.SystemRandom.__init__

    def _spy_init(self, *args, **kwargs):
        calls.append(1)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(secrets.SystemRandom, "__init__", _spy_init)
    generate_keypair(bits=64)
    assert len(calls) == 1
