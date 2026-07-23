"""Classical trial-division factoring, with real (measured, not estimated) timing.

Trial division is only tractable here up to roughly 30-bit moduli; that's
the point of the benchmark, which is to show measured wall-clock time
exploding empirically as key size grows, not to factor anything
production-sized. Comparisons at real-world key sizes (1024/2048-bit) use
the theoretical complexity curves in ``complexity.py`` instead, since
actually running trial division at that scale is not feasible.
"""

from __future__ import annotations

import time

from cryptosentry.rsa import generate_keypair


def trial_division_factor(n: int) -> tuple[int, int]:
    """Returns (p, q) such that p * q == n, or (1, n) if n is prime/1."""
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return i, n // i
        i += 2
    return 1, n


def benchmark_trial_division(bit_sizes: list[int], seed: int = 42) -> dict[int, float]:
    """For each modulus bit size, generate a real keypair and time factoring it."""
    results: dict[int, float] = {}
    for bits in bit_sizes:
        keypair = generate_keypair(bits=bits, seed=seed)
        start = time.perf_counter()
        p, q = trial_division_factor(keypair.n)
        elapsed = time.perf_counter() - start
        if p * q != keypair.n:
            raise RuntimeError(f"factoring produced an incorrect result for n={keypair.n}")
        results[bits] = elapsed
    return results
