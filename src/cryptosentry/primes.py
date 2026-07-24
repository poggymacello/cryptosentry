"""Miller-Rabin primality testing and random prime generation.

Implemented from scratch rather than pulled from a crypto library, since
the point of this project is to demonstrate real RSA mechanics rather than
call a black box.
"""

from __future__ import annotations

import random
import secrets

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def is_probable_prime(n: int, rounds: int = 20, rng: random.Random | None = None) -> bool:
    """Miller-Rabin primality test. False-positive probability <= 4^-rounds."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # secrets.SystemRandom is a random.Random subclass backed by the OS
    # CSPRNG (os.urandom) rather than a seedable Mersenne Twister -- the
    # fix for the exact key-generation vulnerability class this project
    # studies (see README's "What changed from v1"). A caller that
    # explicitly wants reproducibility (tests, benchmarks) passes its own
    # random.Random(seed) instance; nothing here defaults to one.
    rng = rng or secrets.SystemRandom()
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rng: random.Random) -> int:
    """Generate a random ``bits``-bit probable prime (top bit and low bit forced to 1)."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rng=rng):
            return candidate
