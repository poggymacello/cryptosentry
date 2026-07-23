"""Textbook complexity formulas for classical vs. quantum integer factoring.

This module does NOT simulate a quantum computer, Shor's algorithm, or any
period-finding routine. There is no quantum hardware or quantum circuit
simulator involved anywhere in this project. What it does is plot the
well-known asymptotic operation-count formulas from the literature, so the
*shape* of the classical-vs-quantum gap is visible at real-world key sizes
where actually running either algorithm is not feasible on a laptop.
"""

from __future__ import annotations

import math


def gnfs_operations(bits: int) -> float:
    """General Number Field Sieve operation count estimate.

    GNFS is the best known classical algorithm for factoring large
    integers. Complexity: L_N[1/3, (64/9)^(1/3)].
    Reference: Lenstra, A.K. and Lenstra, H.W. (eds.), "The Development of
    the Number Field Sieve," Lecture Notes in Mathematics 1554, 1993.
    """
    ln_n = bits * math.log(2)
    c = (64 / 9) ** (1 / 3)
    return math.exp(c * (ln_n ** (1 / 3)) * (math.log(ln_n) ** (2 / 3)))


def shor_operations(bits: int) -> float:
    """Shor's algorithm quantum gate-count estimate: O((log N)^3).

    Reference: Shor, P.W. "Polynomial-Time Algorithms for Prime
    Factorization and Discrete Logarithms on a Quantum Computer," SIAM
    Journal on Computing, 1997.
    """
    ln_n = bits * math.log(2)
    return ln_n**3
