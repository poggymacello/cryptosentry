import pytest

from cryptosentry.rsa import decrypt, encrypt, generate_keypair


def test_keygen_produces_real_distinct_primes_and_valid_modulus():
    keypair = generate_keypair(bits=64, seed=1)
    assert keypair.p != keypair.q
    assert keypair.n == keypair.p * keypair.q
    assert keypair.n.bit_length() in (63, 64)  # product of two 32-bit primes


def test_encrypt_decrypt_round_trip():
    keypair = generate_keypair(bits=128, seed=2)
    message = b"hello rsa"
    ciphertext = encrypt(message, keypair.n, keypair.e)
    recovered = decrypt(ciphertext, keypair.n, keypair.d)
    assert recovered == message


def test_round_trip_across_multiple_messages_and_seeds():
    for seed in (1, 2, 3, 4, 5):
        keypair = generate_keypair(bits=128, seed=seed)
        for message in (b"a", b"test message", b"rsa bytes here"):
            ciphertext = encrypt(message, keypair.n, keypair.e)
            assert decrypt(ciphertext, keypair.n, keypair.d) == message


def test_leading_zero_bytes_are_not_preserved():
    # documented limitation of raw/unpadded RSA: a message and the same
    # message with leading zero bytes stripped encode to the same integer,
    # so decrypt cannot tell them apart. Real RSA uses fixed-length padded
    # encoding (e.g. OAEP) specifically to avoid this.
    keypair = generate_keypair(bits=128, seed=8)
    padded = b"\x00\x01rsa"
    stripped = b"\x01rsa"
    ciphertext = encrypt(padded, keypair.n, keypair.e)
    assert decrypt(ciphertext, keypair.n, keypair.d) == stripped


def test_ciphertext_differs_from_plaintext_and_is_deterministic():
    keypair = generate_keypair(bits=64, seed=6)
    message = b"secret"
    c1 = encrypt(message, keypair.n, keypair.e)
    c2 = encrypt(message, keypair.n, keypair.e)
    assert c1 == c2  # textbook RSA is deterministic, no padding/randomization
    assert c1 != int.from_bytes(message, "big")


def test_message_too_long_for_key_raises():
    keypair = generate_keypair(bits=32, seed=7)
    too_long = b"this message is definitely too long for a 32-bit key"
    with pytest.raises(ValueError):
        encrypt(too_long, keypair.n, keypair.e)
