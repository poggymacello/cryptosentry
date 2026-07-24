"""Plots: measured classical factoring time, and theoretical complexity comparison."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptosentry.complexity import gnfs_operations, shor_operations


def plot_empirical_factoring_time(results: dict[int, float], out_path: Path) -> None:
    bit_sizes = sorted(results.keys())
    times = [results[b] for b in bit_sizes]

    plt.figure(figsize=(7, 5))
    plt.plot(bit_sizes, times, marker="o")
    plt.yscale("log")
    plt.xlabel("RSA modulus size (bits)")
    plt.ylabel("trial-division factoring time (seconds, log scale)")
    plt.title("measured classical factoring time vs. key size")
    plt.grid(True, which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_complexity_comparison(bit_range: list[int], out_path: Path) -> None:
    gnfs = [gnfs_operations(b) for b in bit_range]
    shor = [shor_operations(b) for b in bit_range]

    plt.figure(figsize=(7, 5))
    plt.plot(bit_range, gnfs, label="GNFS (best known classical), estimated operations")
    plt.plot(bit_range, shor, label="Shor's algorithm, estimated quantum gates")
    plt.yscale("log")
    plt.xlabel("RSA modulus size (bits)")
    plt.ylabel("estimated operation count (log scale)")
    plt.title("classical vs. quantum factoring cost: theoretical estimates only")
    plt.legend()
    plt.grid(True, which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_algorithm_share_by_month(
    share_by_month: dict[str, dict[str, float]], out_path: Path
) -> None:
    """Real RSA-vs-EC issuance share within the surveyed CT log snapshot."""
    months = sorted(share_by_month.keys())
    algorithms = sorted({algo for shares in share_by_month.values() for algo in shares})

    plt.figure(figsize=(9, 5))
    for algo in algorithms:
        values = [share_by_month[m].get(algo, 0.0) * 100 for m in months]
        plt.plot(months, values, marker="o", label=algo)
    plt.xticks(rotation=45, ha="right")
    plt.xlabel("CT log timestamp (year-month)")
    plt.ylabel("share of surveyed certificates (%)")
    plt.title("RSA vs. EC key algorithm share, real CT log snapshot")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
