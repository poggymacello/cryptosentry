"""Textbook RSA over real, randomly generated bignum primes.

This is unpadded ("schoolbook") RSA: no OAEP padding, no side-channel
hardening, no key-size validation beyond what's needed for the demo to
round-trip correctly. It is not production cryptography — see the README's
Limitations section.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from cryptosentry.primes import generate_prime

PUBLIC_EXPONENT = 65537


@dataclass(frozen=True)
class KeyPair:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def _modinv(e: int, phi: int) -> int:
    g, x, _ = _egcd(e, phi)
    if g != 1:
        raise ValueError("e and phi(n) are not coprime; cannot invert")
    return x % phi


def generate_keypair(bits: int = 256, seed: int = 42) -> KeyPair:
    """Generate a real RSA keypair with ``bits``-bit modulus (``bits // 2``-bit primes)."""
    rng = random.Random(seed)
    e = PUBLIC_EXPONENT
    while True:
        p = generate_prime(bits // 2, rng)
        q = generate_prime(bits // 2, rng)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            break
    n = p * q
    d = _modinv(e, phi)
    return KeyPair(n=n, e=e, d=d, p=p, q=q)


def encrypt(message: bytes, n: int, e: int) -> int:
    m = int.from_bytes(message, "big")
    if m >= n:
        raise ValueError("message too long for this key size")
    return pow(m, e, n)


def decrypt(ciphertext: int, n: int, d: int) -> bytes:
    """Decrypt back to bytes.

    Note: this raw/unpadded scheme cannot distinguish a message from the
    same message with leading zero bytes stripped, since both encode to the
    same integer. ``b"\\x00\\x01"`` and ``b"\\x01"`` decrypt identically.
    Real RSA implementations use a fixed-length, padded encoding (e.g.
    PKCS#1 OAEP) specifically to avoid this ambiguity, among other reasons.
    """
    m = pow(ciphertext, d, n)
    length = max(1, (m.bit_length() + 7) // 8)
    return m.to_bytes(length, "big")
