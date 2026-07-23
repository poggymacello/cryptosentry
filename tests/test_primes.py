import random

from cryptosentry.primes import generate_prime, is_probable_prime

KNOWN_PRIMES = [2, 3, 5, 7, 11, 97, 7919, 104729]
KNOWN_COMPOSITES = [4, 6, 8, 9, 100, 7920, 104730, 1000003 * 1000033]


def test_known_primes_are_identified_as_prime():
    for p in KNOWN_PRIMES:
        assert is_probable_prime(p)


def test_known_composites_are_identified_as_composite():
    for c in KNOWN_COMPOSITES:
        assert not is_probable_prime(c)


def test_zero_and_one_are_not_prime():
    assert not is_probable_prime(0)
    assert not is_probable_prime(1)


def test_generate_prime_returns_correct_bit_length_and_is_prime():
    rng = random.Random(1)
    for bits in (16, 32, 64):
        p = generate_prime(bits, rng)
        assert p.bit_length() == bits
        assert is_probable_prime(p)
        assert p % 2 == 1
